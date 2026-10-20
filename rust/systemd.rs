//! A product service run by a systemd unit (system or `--user`) is that unit's
//! to stop and start. Computer up to 1.0.47 does not know about systemd: it
//! launches this installer inside the unit's control group and stops itself
//! with `raft-computer stop`. Under the default `KillMode=control-group` the
//! unit's stop then kills the installer too, and `Restart=always` brings the
//! old version back while the swap is in flight (or `Restart=on-failure`
//! leaves it stopped). So, on Linux: leave the unit's control group first
//! (`systemd-run --scope`), and stop/start the product through `systemctl`.
//! When the installer cannot leave, it refuses before stopping anything.
use crate::{Result, config::Config};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Set on the copy re-executed in its own scope, so it never tries again.
pub const ESCAPED_ENV: &str = "RAFT_COMPUTER_INSTALLER_SCOPE";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServiceUnit {
    /// Unit of the per-user manager (`systemctl --user`).
    pub user: bool,
    pub name: String,
    /// The unit's control-group path; processes below it belong to the unit.
    pub cgroup: String,
}

/// The systemd control-group path in `/proc/<pid>/cgroup` (v2 `0::`, or the v1
/// `name=systemd` hierarchy).
pub fn cgroup_path(content: &str) -> Option<String> {
    let mut v1 = None;
    for line in content.lines() {
        let mut parts = line.splitn(3, ':');
        let (Some(id), Some(controllers), Some(path)) = (parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        if id == "0" && controllers.is_empty() {
            return Some(path.to_string());
        }
        if controllers == "name=systemd" {
            v1 = Some(path.to_string());
        }
    }
    v1
}

/// The innermost `*.service` unit a control-group path belongs to, other than
/// a per-user manager (`user@UID.service`) itself.
pub fn unit_of_cgroup(path: &str) -> Option<ServiceUnit> {
    let parts: Vec<&str> = path.split('/').collect();
    let user_manager = parts
        .iter()
        .position(|part| part.starts_with("user@") && part.ends_with(".service"));
    let index = parts.iter().rposition(|part| {
        part.ends_with(".service") && !(part.starts_with("user@") && part.len() > ".service".len())
    })?;
    if user_manager.is_some_and(|manager| index <= manager) {
        return None;
    }
    let name = parts[index];
    if name == ".service" || name.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return None;
    }
    Some(ServiceUnit {
        user: user_manager.is_some(),
        name: name.to_string(),
        cgroup: parts[..=index].join("/"),
    })
}

fn inside(path: &str, unit: &ServiceUnit) -> bool {
    path == unit.cgroup || path.starts_with(&format!("{}/", unit.cgroup))
}

#[cfg(target_os = "linux")]
fn cgroup_of(pid: u32) -> Option<String> {
    cgroup_path(&std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?)
}

#[cfg(not(target_os = "linux"))]
fn cgroup_of(_pid: u32) -> Option<String> {
    None
}

/// The parent pid from `/proc/<pid>/stat` (the field after the command name,
/// which may itself contain spaces and parentheses).
pub fn parent_from_stat(stat: &str) -> Option<u32> {
    let rest = &stat[stat.rfind(')')? + 1..];
    rest.split_whitespace().nth(1)?.parse().ok()
}

/// Shell interpreters a unit's `ExecStart=` script runs under.
pub fn is_shell_name(name: &str) -> bool {
    ["sh", "bash", "dash", "zsh", "ash", "ksh", "mksh", "busybox"].contains(&name)
}

#[cfg(target_os = "linux")]
fn parent_of(pid: u32) -> Option<u32> {
    parent_from_stat(&std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?)
}

#[cfg(target_os = "linux")]
fn is_shell(pid: u32) -> bool {
    std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .and_then(|path| {
            path.file_name()
                .map(|name| name.to_string_lossy().into_owned())
        })
        .is_some_and(|name| is_shell_name(&name))
}

#[cfg(not(target_os = "linux"))]
fn parent_of(_pid: u32) -> Option<u32> {
    None
}

#[cfg(not(target_os = "linux"))]
fn is_shell(_pid: u32) -> bool {
    false
}

/// The unit running the installed product's service, if any: a unit whose
/// main process is the product itself, or a shell script that started the
/// product as its direct child (`ExecStart=` a wrapper without `exec`). A
/// product started from inside some other service (a CI runner, a desktop
/// app's unit) is not that unit's to stop or start.
pub async fn product_unit(cfg: &Config) -> Result<Option<ServiceUnit>> {
    let processes = crate::host::installed_product_processes(cfg)?;
    for process in &processes {
        let Some(unit) = cgroup_of(process.pid).as_deref().and_then(unit_of_cgroup) else {
            continue;
        };
        let Some(main) = main_pid(&unit).await else {
            continue;
        };
        if processes.iter().any(|product| product.pid == main)
            || (parent_of(process.pid) == Some(main) && is_shell(main))
        {
            return Ok(Some(unit));
        }
    }
    Ok(None)
}

/// `systemctl [--user] show -p MainPID --value -- <unit>`; None when unknown.
async fn main_pid(unit: &ServiceUnit) -> Option<u32> {
    let mut command = command("systemctl", unit);
    command
        .args(["show", "-p", "MainPID", "--value", "--", unit.name.as_str()])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let output = tokio::time::timeout(Duration::from_secs(15), command.output())
        .await
        .ok()?
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse::<u32>()
        .ok()
        .filter(|pid| *pid > 0)
}

/// Whether this process would be stopped together with the unit.
pub fn self_inside(unit: &ServiceUnit) -> bool {
    cgroup_of(std::process::id()).is_some_and(|path| inside(&path, unit))
}

fn manager_args(unit: &ServiceUnit) -> Vec<String> {
    if unit.user {
        vec!["--user".into()]
    } else {
        vec![]
    }
}

fn command(program: &str, unit: &ServiceUnit) -> tokio::process::Command {
    let mut command = tokio::process::Command::new(program);
    command.args(manager_args(unit));
    // A user manager is found through the runtime directory; a service it
    // started has one, a recovery run from elsewhere may not.
    #[cfg(unix)]
    if unit.user && std::env::var_os("XDG_RUNTIME_DIR").is_none() {
        command.env(
            "XDG_RUNTIME_DIR",
            format!("/run/user/{}", unsafe { libc::getuid() }),
        );
    }
    command
}

/// `systemctl [--user] stop|start <unit>`, bounded.
pub async fn systemctl(unit: &ServiceUnit, action: &str) -> Result<()> {
    let mut command = command("systemctl", unit);
    command
        .args([action, "--", unit.name.as_str()])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped());
    let output = tokio::time::timeout(Duration::from_secs(120), command.output())
        .await
        .map_err(|_| {
            k_carrier::error::invalid(format!("systemctl {action} {} timed out", unit.name))
        })??;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let line = stderr.lines().next().unwrap_or("").trim();
        return Err(k_carrier::error::invalid(format!(
            "systemctl {action} {} failed: {line}",
            unit.name
        )));
    }
    Ok(())
}

pub enum Escape {
    /// The copy is running in its own scope and carries the operation.
    Running,
    /// `systemd-run` (or the copy) exited within the first seconds.
    Exited(Option<i32>),
    /// Nothing could be started.
    Failed,
}

/// Re-run this invocation in a transient scope outside the unit.
pub async fn escape(unit: &ServiceUnit, args: &[String]) -> Escape {
    let Ok(executable) = std::env::current_exe() else {
        return Escape::Failed;
    };
    let mut command = command("systemd-run", unit);
    command
        .args(["--scope", "--quiet", "--collect"])
        .arg("--")
        .arg(executable)
        .args(args)
        .env(ESCAPED_ENV, "1")
        .stdin(std::process::Stdio::null());
    let Ok(mut child) = command.spawn() else {
        return Escape::Failed;
    };
    // systemd-run fails fast when it cannot create the scope (no manager,
    // not permitted); a copy still running after that is in its scope. A
    // copy that already finished may have written this request's receipt.
    match tokio::time::timeout(Duration::from_secs(5), child.wait()).await {
        Ok(Ok(status)) => Escape::Exited(status.code()),
        Ok(Err(_)) => Escape::Failed,
        Err(_) => Escape::Running,
    }
}

/// The refusal when the product's unit would stop this installer with it.
pub fn confinement_reason(unit: &ServiceUnit) -> String {
    let manager = if unit.user {
        "systemctl --user"
    } else {
        "systemctl"
    };
    format!(
        "The Computer service runs in systemd unit {name}, which would stop the upgrade together with the service, and the upgrade could not move out of it. Upgrade from the host: `{manager} stop {name}`, run the install command, then `{manager} start {name}`.",
        name = unit.name
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_and_user_units_are_found_and_the_user_manager_is_not_a_unit() {
        assert_eq!(
            unit_of_cgroup("/system.slice/raft-computer.service"),
            Some(ServiceUnit {
                user: false,
                name: "raft-computer.service".into(),
                cgroup: "/system.slice/raft-computer.service".into(),
            })
        );
        assert_eq!(
            unit_of_cgroup("/user.slice/user-1001.slice/user@1001.service/app.slice/raft.service"),
            Some(ServiceUnit {
                user: true,
                name: "raft.service".into(),
                cgroup: "/user.slice/user-1001.slice/user@1001.service/app.slice/raft.service"
                    .into(),
            })
        );
        assert_eq!(
            unit_of_cgroup(
                "/user.slice/user-1001.slice/user@1001.service/app.slice/app-gnome-term.scope"
            ),
            None,
            "a terminal session"
        );
        assert_eq!(
            unit_of_cgroup("/user.slice/user-1001.slice/user@1001.service/init.scope"),
            None
        );
        assert_eq!(unit_of_cgroup("/init.scope"), None);
        assert_eq!(
            unit_of_cgroup("/user.slice/user-1001.slice/session-3.scope"),
            None
        );
    }

    #[test]
    fn processes_below_a_unit_belong_to_it() {
        let unit = unit_of_cgroup("/system.slice/raft-computer.service").unwrap();
        assert!(inside("/system.slice/raft-computer.service", &unit));
        assert!(inside("/system.slice/raft-computer.service/sub", &unit));
        assert!(!inside("/system.slice/raft-computer.service2", &unit));
        assert!(!inside("/system.slice/run-r1.scope", &unit));
    }

    #[test]
    fn cgroup_files_of_both_hierarchies_are_read() {
        assert_eq!(
            cgroup_path("0::/system.slice/raft-computer.service\n").as_deref(),
            Some("/system.slice/raft-computer.service")
        );
        assert_eq!(
            cgroup_path("12:cpu,cpuacct:/x\n1:name=systemd:/system.slice/a.service\n").as_deref(),
            Some("/system.slice/a.service")
        );
        assert_eq!(cgroup_path(""), None);
    }

    #[test]
    fn a_wrapper_shell_is_recognized_by_its_parent_pid_and_name() {
        assert_eq!(
            parent_from_stat("4242 (raft-computer) S 4100 4242 4242 0 -1"),
            Some(4100)
        );
        assert_eq!(
            parent_from_stat("4242 (a b) c)) S 77 1 1"),
            Some(77),
            "a command name with spaces and parentheses"
        );
        assert_eq!(parent_from_stat("garbage"), None);
        assert!(is_shell_name("bash") && is_shell_name("sh") && is_shell_name("dash"));
        assert!(
            !is_shell_name("node")
                && !is_shell_name("Runner.Listener")
                && !is_shell_name("raft-desktop")
        );
    }

    #[test]
    fn the_refusal_names_the_unit_and_the_manager() {
        let user =
            unit_of_cgroup("/user.slice/user-1.slice/user@1.service/app.slice/rc.service").unwrap();
        assert!(confinement_reason(&user).contains("systemctl --user stop rc.service"));
        assert!(!confinement_reason(&user).chars().any(char::is_control));
    }
}
