use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::sleep;

#[derive(Debug, Clone)]
pub struct SidecarCommand {
    pub name: String,
    pub program: String,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub workdir: Option<PathBuf>,
}

impl SidecarCommand {
    pub fn new(name: impl Into<String>, program: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            program: program.into(),
            args: Vec::new(),
            env: Vec::new(),
            workdir: None,
        }
    }

    pub fn arg(mut self, value: impl Into<String>) -> Self {
        self.args.push(value.into());
        self
    }

    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.push((key.into(), value.into()));
        self
    }

    pub fn workdir(mut self, path: impl Into<PathBuf>) -> Self {
        self.workdir = Some(path.into());
        self
    }

    pub fn with_name(&self, name: impl Into<String>) -> Self {
        let mut cmd = self.clone();
        cmd.name = name.into();
        cmd
    }
}

pub struct SidecarProcess {
    name: String,
    child: Child,
    stdout_task: JoinHandle<()>,
    stderr_task: JoinHandle<()>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SidecarSlot {
    A,
    B,
}

impl SidecarSlot {
    fn other(self) -> Self {
        match self {
            SidecarSlot::A => SidecarSlot::B,
            SidecarSlot::B => SidecarSlot::A,
        }
    }

    fn suffix(self) -> &'static str {
        match self {
            SidecarSlot::A => "a",
            SidecarSlot::B => "b",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct SidecarUpdateOptions {
    pub drain_timeout: Option<Duration>,
}

impl SidecarUpdateOptions {
    pub fn drain_timeout(mut self, timeout: Duration) -> Self {
        self.drain_timeout = Some(timeout);
        self
    }
}

#[derive(Debug, Clone)]
pub struct SidecarUpdateOutcome {
    pub active_slot: SidecarSlot,
    pub active_name: String,
    pub draining_name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SidecarReaperOptions {
    pub interval: Duration,
}

impl SidecarReaperOptions {
    pub fn interval(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }
}

impl Default for SidecarReaperOptions {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(10),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SidecarInstanceStatus {
    pub slot: SidecarSlot,
    pub name: String,
    pub pid: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct SidecarGroupStatus {
    pub group: String,
    pub active: Option<SidecarSlot>,
    pub draining: Option<SidecarSlot>,
    pub instances: Vec<SidecarInstanceStatus>,
}

struct SidecarGroup {
    name: String,
    active: Option<SidecarSlot>,
    slots: HashMap<SidecarSlot, String>,
    draining: Option<SidecarSlot>,
    drain_task: Option<JoinHandle<()>>,
    generation: u64,
}

impl SidecarGroup {
    fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            active: None,
            slots: HashMap::new(),
            draining: None,
            drain_task: None,
            generation: 0,
        }
    }

    fn next_instance_name(&mut self, slot: SidecarSlot) -> String {
        self.generation = self.generation.wrapping_add(1);
        format!("{}-{}-{}", self.name, slot.suffix(), self.generation)
    }

    fn slot_for_name(&self, name: &str) -> Option<SidecarSlot> {
        self.slots
            .iter()
            .find_map(|(slot, slot_name)| (slot_name == name).then_some(*slot))
    }
}

#[derive(Default)]
struct SidecarState {
    processes: HashMap<String, SidecarProcess>,
    groups: HashMap<String, SidecarGroup>,
}

#[derive(Clone, Default)]
pub struct SidecarManager {
    state: Arc<Mutex<SidecarState>>,
}

impl SidecarManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn spawn(&self, cmd: SidecarCommand) -> anyhow::Result<()> {
        if self.contains_process(&cmd.name).await {
            log::warn!("sidecar {} already running, restarting", cmd.name);
            self.stop(&cmd.name).await?;
        }
        let process = spawn_process(&cmd).await?;
        let mut state = self.state.lock().await;
        state.processes.insert(cmd.name.clone(), process);
        Ok(())
    }

    pub async fn stop(&self, name: &str) -> anyhow::Result<()> {
        let process = self.take_process(name).await;
        if let Some(mut process) = process {
            let _ = process.child.start_kill();
            let _ = process.child.wait().await;
            process.stdout_task.abort();
            process.stderr_task.abort();
        }
        Ok(())
    }

    pub async fn restart(&self, cmd: SidecarCommand) -> anyhow::Result<()> {
        self.stop(&cmd.name).await?;
        self.spawn(cmd).await
    }

    pub async fn stop_all(&self) -> anyhow::Result<()> {
        let names: Vec<String> = self
            .state
            .lock()
            .await
            .processes
            .keys()
            .cloned()
            .collect();
        for name in names {
            self.stop(&name).await?;
        }
        Ok(())
    }

    pub async fn stop_group(&self, group: &str) -> anyhow::Result<()> {
        let mut drain_task = None;
        let names = {
            let mut state = self.state.lock().await;
            let group = match state.groups.remove(group) {
                Some(group) => group,
                None => return Ok(()),
            };
            drain_task = group.drain_task;
            group.slots.values().cloned().collect::<Vec<_>>()
        };

        if let Some(task) = drain_task {
            task.abort();
        }

        for name in names {
            self.stop(&name).await?;
        }
        Ok(())
    }

    pub async fn draining_instance(&self, group: &str) -> Option<String> {
        let state = self.state.lock().await;
        let group = state.groups.get(group)?;
        let slot = group.draining?;
        group.slots.get(&slot).cloned()
    }

    pub async fn finish_drain(&self, group: &str) -> anyhow::Result<Option<String>> {
        let (name, drain_task) = {
            let mut state = self.state.lock().await;
            let group = match state.groups.get_mut(group) {
                Some(group) => group,
                None => return Ok(None),
            };
            let slot = match group.draining {
                Some(slot) => slot,
                None => return Ok(None),
            };
            let name = group.slots.get(&slot).cloned();
            group.draining = None;
            let drain_task = group.drain_task.take();
            (name, drain_task)
        };

        if let Some(task) = drain_task {
            task.abort();
        }

        if let Some(name) = name.clone() {
            self.stop(&name).await?;
        }

        Ok(name)
    }

    pub fn spawn_reaper(&self, options: SidecarReaperOptions) -> JoinHandle<()> {
        let manager = self.clone();
        tokio::spawn(async move {
            loop {
                sleep(options.interval).await;
                if let Err(err) = manager.reap_exited().await {
                    log::warn!("sidecar reaper failed: {err}");
                }
            }
        })
    }

    pub async fn group_status(&self, group: &str) -> Option<SidecarGroupStatus> {
        let state = self.state.lock().await;
        let group_state = state.groups.get(group)?;
        let mut instances = Vec::with_capacity(group_state.slots.len());
        for (slot, name) in &group_state.slots {
            let pid = state.processes.get(name).and_then(|process| process.child.id());
            instances.push(SidecarInstanceStatus {
                slot: *slot,
                name: name.clone(),
                pid,
            });
        }
        Some(SidecarGroupStatus {
            group: group_state.name.clone(),
            active: group_state.active,
            draining: group_state.draining,
            instances,
        })
    }

    pub async fn reap_exited(&self) -> anyhow::Result<Vec<String>> {
        let mut exited = Vec::new();
        let mut state = self.state.lock().await;
        let mut to_remove = Vec::new();
        for (name, process) in state.processes.iter_mut() {
            if let Some(status) = process.child.try_wait()? {
                log::warn!("sidecar {} exited with {}", name, status);
                to_remove.push(name.clone());
            }
        }

        for name in to_remove {
            if let Some(process) = state.processes.remove(&name) {
                process.stdout_task.abort();
                process.stderr_task.abort();
            }
            cleanup_group_for_name(&mut state, &name);
            exited.push(name);
        }

        prune_empty_groups(&mut state);
        Ok(exited)
    }

    pub async fn active_instance(&self, group: &str) -> Option<String> {
        let state = self.state.lock().await;
        let group = state.groups.get(group)?;
        let active = group.active?;
        group.slots.get(&active).cloned()
    }

    pub async fn update_ab(
        &self,
        cmd: SidecarCommand,
        options: SidecarUpdateOptions,
    ) -> anyhow::Result<SidecarUpdateOutcome> {
        let group_name = cmd.name.clone();
        let mut stop_names = Vec::new();
        let mut old_active_name = None;
        let mut drain_task = None;
        let (new_slot, new_name) = {
            let mut state = self.state.lock().await;
            let group = state
                .groups
                .entry(group_name.clone())
                .or_insert_with(|| SidecarGroup::new(group_name.clone()));
            if let Some(task) = group.drain_task.take() {
                drain_task = Some(task);
            }
            if let Some(draining_slot) = group.draining.take() {
                if let Some(name) = group.slots.remove(&draining_slot) {
                    stop_names.push(name);
                }
            }
            let new_slot = group.active.map(|slot| slot.other()).unwrap_or(SidecarSlot::A);
            let new_name = group.next_instance_name(new_slot);
            if let Some(name) = group.slots.remove(&new_slot) {
                stop_names.push(name);
            }
            if let Some(active_slot) = group.active {
                old_active_name = group.slots.get(&active_slot).cloned();
            }
            (new_slot, new_name)
        };

        if let Some(task) = drain_task {
            task.abort();
        }

        for name in stop_names {
            self.stop(&name).await?;
        }

        let instance_cmd = cmd.with_name(new_name.clone());
        self.spawn(instance_cmd).await?;

        let mut immediate_stop = None;
        let mut draining_name = None;
        {
            let mut state = self.state.lock().await;
            let group = state
                .groups
                .entry(group_name.clone())
                .or_insert_with(|| SidecarGroup::new(group_name.clone()));
            group.slots.insert(new_slot, new_name.clone());
            group.active = Some(new_slot);

            if let Some(old_name) = old_active_name.clone() {
                if let Some(timeout) = options.drain_timeout {
                    let draining_slot = group.slot_for_name(&old_name);
                    group.draining = draining_slot;
                    draining_name = Some(old_name.clone());
                    let manager = self.clone();
                    let group_name = group_name.clone();
                    let old_name_clone = old_name.clone();
                    let drain_task = tokio::spawn(async move {
                        tokio::time::sleep(timeout).await;
                        let _ = manager.stop(&old_name_clone).await;
                        let mut state = manager.state.lock().await;
                        if let Some(group) = state.groups.get_mut(&group_name) {
                            let still_draining = group
                                .draining
                                .and_then(|slot| group.slots.get(&slot))
                                .map(|name| name == &old_name_clone)
                                .unwrap_or(false);
                            if still_draining {
                                group.draining = None;
                                group.drain_task = None;
                            }
                        }
                    });
                    group.drain_task = Some(drain_task);
                } else {
                    immediate_stop = Some(old_name);
                }
            }
        }

        if let Some(name) = immediate_stop {
            self.stop(&name).await?;
        }

        Ok(SidecarUpdateOutcome {
            active_slot: new_slot,
            active_name: new_name,
            draining_name,
        })
    }

    async fn contains_process(&self, name: &str) -> bool {
        let state = self.state.lock().await;
        state.processes.contains_key(name)
    }

    async fn take_process(&self, name: &str) -> Option<SidecarProcess> {
        let mut state = self.state.lock().await;
        let process = state.processes.remove(name);
        if process.is_some() {
            cleanup_group_for_name(&mut state, name);
        }
        process
    }
}

async fn stream_logs(name: String, stream: impl tokio::io::AsyncRead + Unpin, stdout: bool) {
    let mut reader = BufReader::new(stream).lines();
    while let Ok(Some(line)) = reader.next_line().await {
        if stdout {
            log::info!("sidecar {name}: {line}");
        } else {
            log::warn!("sidecar {name} err: {line}");
        }
    }
}

async fn spawn_process(cmd: &SidecarCommand) -> anyhow::Result<SidecarProcess> {
    let mut command = Command::new(&cmd.program);
    command.args(&cmd.args);
    for (key, value) in &cmd.env {
        command.env(key, value);
    }
    if let Some(dir) = &cmd.workdir {
        command.current_dir(dir);
    }
    command.stdout(std::process::Stdio::piped());
    command.stderr(std::process::Stdio::piped());

    let mut child = command.spawn()?;
    let stdout = child.stdout.take().ok_or_else(|| anyhow::anyhow!("stdout unavailable"))?;
    let stderr = child.stderr.take().ok_or_else(|| anyhow::anyhow!("stderr unavailable"))?;

    let name = cmd.name.clone();
    let stdout_task = tokio::spawn(stream_logs(name.clone(), stdout, true));
    let stderr_task = tokio::spawn(stream_logs(name.clone(), stderr, false));

    Ok(SidecarProcess {
        name: cmd.name.clone(),
        child,
        stdout_task,
        stderr_task,
    })
}

fn cleanup_group_for_name(state: &mut SidecarState, name: &str) {
    for group in state.groups.values_mut() {
        if let Some(slot) = group.slot_for_name(name) {
            group.slots.remove(&slot);
            if group.active == Some(slot) {
                group.active = group.slots.keys().next().copied();
            }
            if group.draining == Some(slot) {
                group.draining = None;
                if let Some(task) = group.drain_task.take() {
                    task.abort();
                }
            }
            break;
        }
    }
}

fn prune_empty_groups(state: &mut SidecarState) {
    state.groups.retain(|_, group| {
        if group.slots.is_empty() {
            group.active = None;
            group.draining = None;
            if let Some(task) = group.drain_task.take() {
                task.abort();
            }
        }
        !group.slots.is_empty()
    });
}
