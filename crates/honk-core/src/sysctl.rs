//! Sysctl writes with a command fallback for restricted procfs mounts.

fn proc_path(key: &str) -> String {
    format!("/proc/sys/{}", key.replace('.', "/"))
}

pub(crate) fn set_sysctl(key: &str, value: &str) -> anyhow::Result<()> {
    set_sysctl_at(key, value, &proc_path(key))
}

fn set_sysctl_at(key: &str, value: &str, path: &str) -> anyhow::Result<()> {
    // Prefer /proc/sys because the standalone `sysctl` binary may not be on
    // PATH in minimal environments (e.g. NixOS containers).
    if let Err(e) = std::fs::write(path, format!("{}\n", value)) {
        let output = std::process::Command::new("sysctl")
            .args(["-w", &format!("{}={}", key, value)])
            .output()?;
        if !output.status.success() {
            anyhow::bail!(
                "sysctl -w {}={} failed: {} (proc write also failed: {})",
                key,
                value,
                String::from_utf8_lossy(&output.stderr),
                e
            );
        }
    }
    Ok(())
}

#[cfg(feature = "ebpf")]
pub(crate) fn require_off(key: &str, optional: bool) -> anyhow::Result<()> {
    use anyhow::Context as _;

    let path = proc_path(key);
    if optional
        && !std::path::Path::new(&path)
            .try_exists()
            .with_context(|| format!("inspect {key} in daens"))?
    {
        return Ok(());
    }
    set_sysctl_at(key, "0", &path).with_context(|| format!("disable {key} in daens"))?;
    let actual =
        std::fs::read_to_string(&path).with_context(|| format!("verify {key} in daens"))?;
    anyhow::ensure!(actual.trim() == "0", "{key} remains enabled in daens");
    Ok(())
}

/// Keep RA reception alive on a WAN interface across the datapath's
/// all.forwarding=1 pin: with the stock accept_ra=1 the kernel drops RAs
/// once forwarding is on, and networkd's userspace RA disables itself the
/// same way — either path lets the SLAAC default route expire (#46).
#[cfg(feature = "ebpf")]
pub(crate) fn enable_wan_accept_ra(ifname: &str) {
    if let Err(e) = set_sysctl(&format!("net.ipv6.conf.{ifname}.accept_ra"), "2") {
        tracing::warn!("failed to set accept_ra for {ifname}: {e}");
    }
}
