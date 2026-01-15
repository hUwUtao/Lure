use std::collections::HashMap;
use std::path::PathBuf;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

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
}

pub struct SidecarProcess {
    name: String,
    child: Child,
    stdout_task: JoinHandle<()>,
    stderr_task: JoinHandle<()>,
}

#[derive(Default)]
pub struct SidecarManager {
    processes: Mutex<HashMap<String, SidecarProcess>>,
}

impl SidecarManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn spawn(&self, cmd: SidecarCommand) -> anyhow::Result<()> {
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

        let process = SidecarProcess {
            name: cmd.name.clone(),
            child,
            stdout_task,
            stderr_task,
        };

        self.processes
            .lock()
            .await
            .insert(cmd.name.clone(), process);
        Ok(())
    }

    pub async fn stop(&self, name: &str) -> anyhow::Result<()> {
        let mut processes = self.processes.lock().await;
        if let Some(mut process) = processes.remove(name) {
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
            .processes
            .lock()
            .await
            .keys()
            .cloned()
            .collect();
        for name in names {
            self.stop(&name).await?;
        }
        Ok(())
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
