use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;

use crate::config::{CrossplayConfig, SidecarGroupConfig};
use crate::crossplay::sidecar::{
    SidecarCommand, SidecarManager, SidecarReaperOptions, SidecarSlot, SidecarUpdateOptions,
};

const SIDECAR_HOST_PREFIX: &str = "sidecar.";

#[derive(Debug, Clone)]
pub struct SidecarResolvedEndpoint {
    pub group: String,
    pub endpoint: SocketAddr,
    pub endpoint_host: String,
}

#[derive(Clone)]
pub struct CrossplaySupervisor {
    inner: Arc<CrossplaySupervisorInner>,
}

struct CrossplaySupervisorInner {
    manager: SidecarManager,
    groups: HashMap<String, SidecarGroupState>,
    sessions: Mutex<HashMap<String, usize>>,
    drain_timeout_default: Option<Duration>,
    reaper_interval: Duration,
}

struct SidecarGroupState {
    config: SidecarGroupConfig,
    listen_a: Option<SocketAddr>,
    listen_b: Option<SocketAddr>,
}

impl CrossplaySupervisor {
    pub fn from_config(config: Option<&CrossplayConfig>) -> Option<Self> {
        let config = config?;
        if config.sidecars.is_empty() {
            return None;
        }

        let mut groups = HashMap::new();
        for group in &config.sidecars {
            let listen_a = parse_socket_addr(&group.listen_a);
            let listen_b = parse_socket_addr(&group.listen_b);
            if listen_a.is_none() && listen_b.is_none() {
                log::warn!("crossplay sidecar {} missing listen address", group.name);
            }
            groups.insert(
                group.name.clone(),
                SidecarGroupState {
                    config: group.clone(),
                    listen_a,
                    listen_b,
                },
            );
        }

        Some(Self {
            inner: Arc::new(CrossplaySupervisorInner {
                manager: SidecarManager::new(),
                groups,
                sessions: Mutex::new(HashMap::new()),
                drain_timeout_default: config.drain_timeout_secs.map(Duration::from_secs),
                reaper_interval: config
                    .reaper_interval_secs
                    .map(Duration::from_secs)
                    .unwrap_or(Duration::from_secs(10)),
            }),
        })
    }

    pub async fn start(&self) -> anyhow::Result<()> {
        self.inner
            .manager
            .spawn_reaper(SidecarReaperOptions::default().interval(self.inner.reaper_interval));

        for group in self.inner.groups.values() {
            if group.config.auto_start {
                let name = group.config.name.clone();
                if let Err(err) = self.update_group(&name).await {
                    log::warn!("crossplay sidecar {name} failed to start: {err}");
                }
            }
        }
        Ok(())
    }

    pub async fn update_group(&self, name: &str) -> anyhow::Result<()> {
        let group = self
            .inner
            .groups
            .get(name)
            .ok_or_else(|| anyhow::anyhow!("crossplay sidecar '{name}' not configured"))?;
        let next_slot = self.next_slot(name).await;
        let cmd = build_command(&group.config, next_slot, group.listen_for(next_slot))?;
        let drain_timeout = group
            .config
            .drain_timeout_secs
            .map(Duration::from_secs)
            .or(self.inner.drain_timeout_default);
        let mut options = SidecarUpdateOptions::default();
        if let Some(timeout) = drain_timeout {
            options = options.drain_timeout(timeout);
        }
        let outcome = self.inner.manager.update_ab(cmd, options).await?;
        log::info!(
            "crossplay sidecar {} now active: {} (draining: {:?})",
            name,
            outcome.active_name,
            outcome.draining_name
        );
        Ok(())
    }

    pub async fn active_addr(&self, name: &str) -> Option<SocketAddr> {
        let group = self.inner.groups.get(name)?;
        let status = self.inner.manager.group_status(name).await?;
        let active = status.active?;
        group.listen_for(active)
    }

    pub async fn resolve_sidecar_endpoint(
        &self,
        endpoint_host: &str,
    ) -> anyhow::Result<Option<SidecarResolvedEndpoint>> {
        let group = match parse_sidecar_group(endpoint_host) {
            Some(group) => group,
            None => return Ok(None),
        };

        self.ensure_running(&group).await?;

        let addr = self
            .active_addr(&group)
            .await
            .ok_or_else(|| anyhow::anyhow!("crossplay sidecar '{group}' has no active address"))?;

        let endpoint = addr;
        Ok(Some(SidecarResolvedEndpoint {
            group,
            endpoint,
            endpoint_host: addr.ip().to_string(),
        }))
    }

    pub async fn session_guard(&self, group: &str) -> Option<CrossplaySessionGuard> {
        if !self.inner.groups.contains_key(group) {
            return None;
        }
        {
            let mut sessions = self.inner.sessions.lock().await;
            let entry = sessions.entry(group.to_string()).or_insert(0);
            *entry = entry.saturating_add(1);
        }
        Some(CrossplaySessionGuard {
            group: group.to_string(),
            inner: Arc::clone(&self.inner),
        })
    }

    async fn ensure_running(&self, name: &str) -> anyhow::Result<()> {
        if let Some(status) = self.inner.manager.group_status(name).await {
            if status.active.is_some() {
                return Ok(());
            }
        }
        self.update_group(name).await
    }

    async fn next_slot(&self, name: &str) -> SidecarSlot {
        self.inner
            .manager
            .group_status(name)
            .await
            .and_then(|status| status.active)
            .map(SidecarSlot::other)
            .unwrap_or(SidecarSlot::A)
    }
}

struct CrossplaySessionGuard {
    group: String,
    inner: Arc<CrossplaySupervisorInner>,
}

impl Drop for CrossplaySessionGuard {
    fn drop(&mut self) {
        let group = self.group.clone();
        let inner = Arc::clone(&self.inner);
        tokio::spawn(async move {
            let should_finish = {
                let mut sessions = inner.sessions.lock().await;
                let entry = sessions.entry(group.clone()).or_insert(0);
                *entry = entry.saturating_sub(1);
                *entry == 0
            };
            if should_finish {
                let _ = inner.manager.finish_drain(&group).await;
            }
        });
    }
}

impl SidecarGroupState {
    fn listen_for(&self, slot: SidecarSlot) -> Option<SocketAddr> {
        match slot {
            SidecarSlot::A => self.listen_a,
            SidecarSlot::B => self.listen_b,
        }
    }
}

fn parse_socket_addr(value: &Option<String>) -> Option<SocketAddr> {
    value
        .as_ref()
        .and_then(|value| value.trim().parse::<SocketAddr>().ok())
}

fn parse_sidecar_group(host: &str) -> Option<String> {
    host.strip_prefix(SIDECAR_HOST_PREFIX)
        .map(|value| value.trim().to_string())
}

fn build_command(
    config: &SidecarGroupConfig,
    slot: SidecarSlot,
    listen: Option<SocketAddr>,
) -> anyhow::Result<SidecarCommand> {
    let listen = listen.ok_or_else(|| {
        anyhow::anyhow!("crossplay sidecar {} missing listen address", config.name)
    })?;
    let host = listen.ip().to_string();
    let port = listen.port().to_string();
    let slot_value = slot.suffix().to_string();

    let mut cmd = SidecarCommand::new(&config.name, &config.program);
    for arg in &config.args {
        cmd = cmd.arg(render_template(
            arg,
            &host,
            &port,
            &listen.to_string(),
            &slot_value,
        ));
    }

    for (key, value) in &config.env {
        cmd = cmd.env(
            key.clone(),
            render_template(value, &host, &port, &listen.to_string(), &slot_value),
        );
    }

    if let Some(workdir) = &config.workdir {
        cmd = cmd.workdir(PathBuf::from(workdir));
    }

    Ok(cmd)
}

fn render_template(
    value: &str,
    host: &str,
    port: &str,
    listen: &str,
    slot: &str,
) -> String {
    value
        .replace("{host}", host)
        .replace("{port}", port)
        .replace("{listen}", listen)
        .replace("{slot}", slot)
}
