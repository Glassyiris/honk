//! LAN/WAN interface binding with TC filter attachment.
//!
//! This module defines the data structures and binding logic for attaching
//! eBPF TC classifiers to network interfaces. The actual syscall-level
//! attachment is deferred to a platform-specific implementation via the
//! callback-based `_with` constructors, keeping this module platform-agnostic.
//!
//! # Architecture
//!
//! ```text
//!                     InterfaceBinding
//!                     ┌──────────────────────┐
//!                     │  ifname              │
//!                     │  is_lan: bool        │
//!                     │  tc_ingress_filter   │──▶ TcFilter { handle, priority, direction }
//!                     │  tc_egress_filter    │──▶ TcFilter { handle, priority, direction }
//!                     │  detachers[]         │──▶ Box<dyn FnOnce → Result>
//!                     └──────────────────────┘
//!
//!   LAN binding:  ingress prio=2 handle=0x2023  +  egress prio=1 handle=0x2023
//!   WAN binding:  egress prio=2  handle=0x2023  +  ingress prio=1 handle=0x2023
//! ```

use std::cell::RefCell;
use tracing::{debug, info};

/// Parent handle for ingress TC qdisc — filter attach point for ingress direction.
pub const HANDLE_MIN_INGRESS: u32 = 0xFFFF_0000;

/// Parent handle for egress TC qdisc — filter attach point for egress direction.
pub const HANDLE_MIN_EGRESS: u32 = 0x0001_0000;

/// Well-known filter handle used by honk for BPF TC classifiers.
pub const HONK_FILTER_HANDLE: u32 = 0x2023;

/// Direction of a TC classifier filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcDirection {
    /// Ingress (incoming) traffic.
    Ingress,
    /// Egress (outgoing) traffic.
    Egress,
}

/// Metadata for an attached eBPF TC classifier filter.
///
/// This struct captures everything needed to identify and manage a single
/// BPF TC filter on a network interface.
#[derive(Debug, Clone)]
pub struct TcFilter {
    /// File descriptor of the loaded BPF program (0 if not yet attached).
    pub prog_fd: i32,
    /// Human-readable name of this filter (e.g. "lan-ingress-eth0").
    pub name: String,
    /// TC filter handle — uniquely identifies this filter under its parent qdisc.
    pub handle: u32,
    /// Priority value; lower numeric values are processed first.
    pub priority: u16,
    /// Traffic direction this filter is applied to.
    pub direction: TcDirection,
}

/// Type alias for a deferred detach callback produced during attachment.
type DetachCallback = Box<dyn FnOnce() -> anyhow::Result<()> + Send>;

/// Binds eBPF TC classifiers to a network interface (LAN or WAN role).
///
/// An `InterfaceBinding` tracks the filters attached to one interface and
/// provides methods for their eventual removal.
///
/// # Usage (platform-agnostic / no-op)
///
/// ```ignore
/// let binding = InterfaceBinding::bind_lan("eth0")?;
/// // ... later ...
/// binding.detach()?;
/// ```
///
/// # Usage (with platform attachment)
///
/// ```ignore
/// let binding = InterfaceBinding::bind_lan_with("eth0", |filter, parent| {
///     // platform-specific: call netlink to attach `filter` at `parent`
///     // return a closure that removes the filter
///     Ok(Box::new(|| { /* netlink delete */ Ok(()) }))
/// })?;
/// ```
pub struct InterfaceBinding {
    /// Name of the bound network interface.
    pub ifname: String,
    /// Whether this binding is for a LAN (true) or WAN (false) interface.
    pub is_lan: bool,
    /// Ingress TC filter metadata, if any.
    pub tc_ingress_filter: Option<TcFilter>,
    /// Egress TC filter metadata, if any.
    pub tc_egress_filter: Option<TcFilter>,
    /// Deferred detach callbacks collected during `*_with` construction.
    /// Wrapped in `Option` so `detach_fn` can take ownership via `RefCell::take`.
    detachers: RefCell<Option<Vec<DetachCallback>>>,
}

impl InterfaceBinding {
    /// Create a LAN binding for `ifname` without performing platform-specific
    /// filter attachment.
    ///
    /// Creates metadata for:
    /// - Ingress filter: priority 2, handle [`HONK_FILTER_HANDLE`]
    /// - Egress filter:  priority 1, handle [`HONK_FILTER_HANDLE`]
    pub fn bind_lan(ifname: &str) -> anyhow::Result<Self> {
        info!("Bind to LAN: {ifname}");

        Ok(Self {
            ifname: ifname.to_string(),
            is_lan: true,
            tc_ingress_filter: Some(TcFilter {
                prog_fd: 0,
                name: format!("lan-ingress-{ifname}"),
                handle: HONK_FILTER_HANDLE,
                priority: 2,
                direction: TcDirection::Ingress,
            }),
            tc_egress_filter: Some(TcFilter {
                prog_fd: 0,
                name: format!("lan-egress-{ifname}"),
                handle: HONK_FILTER_HANDLE,
                priority: 1,
                direction: TcDirection::Egress,
            }),
            detachers: RefCell::new(Some(Vec::new())),
        })
    }

    /// Create a WAN binding for `ifname` without performing platform-specific
    /// filter attachment.
    ///
    /// Creates metadata for:
    /// - Egress filter:  priority 2, handle [`HONK_FILTER_HANDLE`]
    /// - Ingress filter: priority 1, handle [`HONK_FILTER_HANDLE`]
    pub fn bind_wan(ifname: &str) -> anyhow::Result<Self> {
        info!("Bind to WAN: {ifname}");

        Ok(Self {
            ifname: ifname.to_string(),
            is_lan: false,
            tc_ingress_filter: Some(TcFilter {
                prog_fd: 0,
                name: format!("wan-ingress-{ifname}"),
                handle: HONK_FILTER_HANDLE,
                priority: 1,
                direction: TcDirection::Ingress,
            }),
            tc_egress_filter: Some(TcFilter {
                prog_fd: 0,
                name: format!("wan-egress-{ifname}"),
                handle: HONK_FILTER_HANDLE,
                priority: 2,
                direction: TcDirection::Egress,
            }),
            detachers: RefCell::new(Some(Vec::new())),
        })
    }
}

impl InterfaceBinding {
    /// Create a LAN binding, calling `attach_fn` for each filter to perform
    /// platform-specific TC attachment.
    ///
    /// `attach_fn` receives the filter metadata and parent handle and should
    /// return a closure that will detach the filter (called during `detach()`).
    ///
    /// Filter order:
    /// 1. Ingress at [`HANDLE_MIN_INGRESS`] with priority 2
    /// 2. Egress  at [`HANDLE_MIN_EGRESS`]  with priority 1
    pub fn bind_lan_with<F>(ifname: &str, attach_fn: F) -> anyhow::Result<Self>
    where
        F: Fn(&TcFilter, u32) -> anyhow::Result<DetachCallback>,
    {
        info!("Bind to LAN (with attach): {ifname}");

        let ingress = TcFilter {
            prog_fd: 0,
            name: format!("lan-ingress-{ifname}"),
            handle: HONK_FILTER_HANDLE,
            priority: 2,
            direction: TcDirection::Ingress,
        };
        let egress = TcFilter {
            prog_fd: 0,
            name: format!("lan-egress-{ifname}"),
            handle: HONK_FILTER_HANDLE,
            priority: 1,
            direction: TcDirection::Egress,
        };

        let ing_detach = attach_fn(&ingress, HANDLE_MIN_INGRESS)?;
        let eg_detach = attach_fn(&egress, HANDLE_MIN_EGRESS)?;
        let detachers = vec![ing_detach, eg_detach];

        Ok(Self {
            ifname: ifname.to_string(),
            is_lan: true,
            tc_ingress_filter: Some(ingress),
            tc_egress_filter: Some(egress),
            detachers: RefCell::new(Some(detachers)),
        })
    }

    /// Create a WAN binding, calling `attach_fn` for each filter to perform
    /// platform-specific TC attachment.
    ///
    /// `attach_fn` receives the filter metadata and parent handle and should
    /// return a closure that will detach the filter (called during `detach()`).
    ///
    /// Filter order:
    /// 1. Egress  at [`HANDLE_MIN_EGRESS`]  with priority 2
    /// 2. Ingress at [`HANDLE_MIN_INGRESS`] with priority 1
    pub fn bind_wan_with<F>(ifname: &str, attach_fn: F) -> anyhow::Result<Self>
    where
        F: Fn(&TcFilter, u32) -> anyhow::Result<DetachCallback>,
    {
        info!("Bind to WAN (with attach): {ifname}");

        let egress = TcFilter {
            prog_fd: 0,
            name: format!("wan-egress-{ifname}"),
            handle: HONK_FILTER_HANDLE,
            priority: 2,
            direction: TcDirection::Egress,
        };
        let ingress = TcFilter {
            prog_fd: 0,
            name: format!("wan-ingress-{ifname}"),
            handle: HONK_FILTER_HANDLE,
            priority: 1,
            direction: TcDirection::Ingress,
        };

        let eg_detach = attach_fn(&egress, HANDLE_MIN_EGRESS)?;
        let ing_detach = attach_fn(&ingress, HANDLE_MIN_INGRESS)?;
        let detachers = vec![eg_detach, ing_detach];

        Ok(Self {
            ifname: ifname.to_string(),
            is_lan: false,
            tc_ingress_filter: Some(ingress),
            tc_egress_filter: Some(egress),
            detachers: RefCell::new(Some(detachers)),
        })
    }
}

impl InterfaceBinding {
    /// Remove all attached TC filters from the interface.
    ///
    /// Calls each stored detach callback in reverse order and logs the action.
    /// Safe to call multiple times — subsequent calls are no-ops.
    pub fn detach(&self) -> anyhow::Result<()> {
        let maybe_detachers = self.detachers.borrow_mut().take();

        let Some(detachers) = maybe_detachers else {
            debug!(
                "[detach] {ifname}: already detached, skipping",
                ifname = self.ifname
            );
            return Ok(());
        };

        if detachers.is_empty() {
            info!(
                "[detach] {ifname}: no filters to remove",
                ifname = self.ifname
            );
            return Ok(());
        }

        let kind = if self.is_lan { "LAN" } else { "WAN" };
        info!(
            "[detach] {ifname}: removing {n} {kind} TC filter(s)",
            ifname = self.ifname,
            n = detachers.len(),
        );

        let mut first_err: Option<anyhow::Error> = None;
        for detach_fn in detachers.into_iter().rev() {
            if let Err(e) = detach_fn()
                && first_err.is_none()
            {
                first_err = Some(e);
            }
        }

        if let Some(e) = first_err {
            Err(e)
        } else {
            info!(
                "[detach] {ifname}: all {kind} filters removed",
                ifname = self.ifname,
            );
            Ok(())
        }
    }

    /// Return a closure that, when invoked, removes all attached TC filters.
    ///
    /// The returned closure takes ownership of the detach callbacks and can
    /// be registered as a deferred cleanup hook (e.g. in a signal handler or
    /// RAII guard). After this call, subsequent calls to `detach()` or
    /// `detach_fn()` will be no-ops.
    pub fn detach_fn(&self) -> Box<dyn FnOnce() -> anyhow::Result<()> + Send> {
        let maybe_detachers = self.detachers.borrow_mut().take();

        let detachers = maybe_detachers.unwrap_or_default();
        let ifname = self.ifname.clone();
        let is_lan = self.is_lan;

        Box::new(move || {
            if detachers.is_empty() {
                debug!("[detach_fn] {ifname}: no filters to remove");
                return Ok(());
            }

            let kind = if is_lan { "LAN" } else { "WAN" };
            info!(
                "[detach_fn] {ifname}: removing {n} {kind} TC filter(s)",
                n = detachers.len(),
            );

            let mut first_err: Option<anyhow::Error> = None;
            for detach_fn in detachers.into_iter().rev() {
                if let Err(e) = detach_fn()
                    && first_err.is_none()
                {
                    first_err = Some(e);
                }
            }

            match first_err {
                Some(e) => Err(e),
                None => {
                    info!("[detach_fn] {ifname}: all {kind} filters removed");
                    Ok(())
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bind_lan_creates_struct() {
        let binding = InterfaceBinding::bind_lan("eth0").expect("bind_lan should succeed");
        assert!(binding.is_lan);
        assert_eq!(binding.ifname, "eth0");

        let ingress = binding
            .tc_ingress_filter
            .as_ref()
            .expect("ingress filter should exist");
        assert_eq!(ingress.handle, HONK_FILTER_HANDLE);
        assert_eq!(ingress.priority, 2);
        assert_eq!(ingress.direction, TcDirection::Ingress);
        assert!(ingress.name.contains("lan-ingress"));

        let egress = binding
            .tc_egress_filter
            .as_ref()
            .expect("egress filter should exist");
        assert_eq!(egress.handle, HONK_FILTER_HANDLE);
        assert_eq!(egress.priority, 1);
        assert_eq!(egress.direction, TcDirection::Egress);
        assert!(egress.name.contains("lan-egress"));
    }

    #[test]
    fn test_bind_wan_creates_struct() {
        let binding = InterfaceBinding::bind_wan("eth1").expect("bind_wan should succeed");
        assert!(!binding.is_lan);
        assert_eq!(binding.ifname, "eth1");

        let ingress = binding
            .tc_ingress_filter
            .as_ref()
            .expect("ingress filter should exist");
        assert_eq!(ingress.priority, 1);
        assert_eq!(ingress.direction, TcDirection::Ingress);
        assert!(ingress.name.contains("wan-ingress"));

        let egress = binding
            .tc_egress_filter
            .as_ref()
            .expect("egress filter should exist");
        assert_eq!(egress.priority, 2);
        assert_eq!(egress.direction, TcDirection::Egress);
        assert!(egress.name.contains("wan-egress"));
    }

    #[test]
    fn test_lan_wan_priority_ordering() {
        let lan = InterfaceBinding::bind_lan("eth0").unwrap();
        assert_eq!(lan.tc_ingress_filter.unwrap().priority, 2);
        assert_eq!(lan.tc_egress_filter.unwrap().priority, 1);

        let wan = InterfaceBinding::bind_wan("eth1").unwrap();
        assert_eq!(wan.tc_ingress_filter.unwrap().priority, 1);
        assert_eq!(wan.tc_egress_filter.unwrap().priority, 2);
    }

    #[test]
    fn test_detach_no_callbacks_is_safe() {
        let binding = InterfaceBinding::bind_lan("eth0").unwrap();
        assert!(binding.detach().is_ok());
        assert!(binding.detach().is_ok());
    }

    #[test]
    fn test_detach_wan_no_callbacks_is_safe() {
        let binding = InterfaceBinding::bind_wan("eth0").unwrap();
        assert!(binding.detach().is_ok());
        assert!(binding.detach().is_ok());
    }

    #[test]
    fn test_detach_fn_no_callbacks_returns_noop() {
        let binding = InterfaceBinding::bind_lan("eth0").unwrap();
        let detach = binding.detach_fn();
        assert!(detach().is_ok());
        let detach2 = binding.detach_fn();
        assert!(detach2().is_ok());
    }

    #[test]
    fn test_detach_fn_consumes_detachers() {
        let binding = InterfaceBinding::bind_lan("eth0").unwrap();
        let _detach = binding.detach_fn();
        assert!(binding.detach().is_ok());
    }

    #[test]
    fn test_bind_lan_with_calls_attach() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let call_count = AtomicUsize::new(0);

        let binding = InterfaceBinding::bind_lan_with("eth0", |filter, parent| {
            call_count.fetch_add(1, Ordering::SeqCst);
            if filter.direction == TcDirection::Ingress {
                assert_eq!(filter.priority, 2);
                assert_eq!(parent, HANDLE_MIN_INGRESS);
            } else {
                assert_eq!(filter.priority, 1);
                assert_eq!(parent, HANDLE_MIN_EGRESS);
            }
            assert_eq!(filter.handle, HONK_FILTER_HANDLE);
            Ok(Box::new(|| Ok(())) as DetachCallback)
        })
        .expect("bind_lan_with should succeed");

        assert_eq!(call_count.load(Ordering::SeqCst), 2);
        assert!(binding.is_lan);
    }

    #[test]
    fn test_bind_wan_with_calls_attach() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let call_count = AtomicUsize::new(0);

        let binding = InterfaceBinding::bind_wan_with("eth1", |filter, parent| {
            call_count.fetch_add(1, Ordering::SeqCst);
            if filter.direction == TcDirection::Egress {
                assert_eq!(filter.priority, 2);
                assert_eq!(parent, HANDLE_MIN_EGRESS);
            } else {
                assert_eq!(filter.priority, 1);
                assert_eq!(parent, HANDLE_MIN_INGRESS);
            }
            Ok(Box::new(|| Ok(())) as DetachCallback)
        })
        .expect("bind_wan_with should succeed");

        assert_eq!(call_count.load(Ordering::SeqCst), 2);
        assert!(!binding.is_lan);
    }

    #[test]
    fn test_detach_runs_stored_callbacks() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        let detach_count = Arc::new(AtomicUsize::new(0));

        let binding = InterfaceBinding::bind_lan_with("eth0", |_filter, _parent| {
            let counter = Arc::clone(&detach_count);
            Ok(Box::new(move || {
                counter.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }) as DetachCallback)
        })
        .unwrap();

        assert_eq!(detach_count.load(Ordering::SeqCst), 0);
        binding.detach().expect("detach should succeed");
        assert_eq!(detach_count.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn test_detach_fn_runs_stored_callbacks() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        let detach_count = Arc::new(AtomicUsize::new(0));

        let binding = InterfaceBinding::bind_wan_with("eth1", |_filter, _parent| {
            let counter = Arc::clone(&detach_count);
            Ok(Box::new(move || {
                counter.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }) as DetachCallback)
        })
        .unwrap();

        let detach = binding.detach_fn();
        assert_eq!(detach_count.load(Ordering::SeqCst), 0);
        detach().expect("detach_fn closure should succeed");
        assert_eq!(detach_count.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn test_tc_direction_eq() {
        assert_eq!(TcDirection::Ingress, TcDirection::Ingress);
        assert_ne!(TcDirection::Ingress, TcDirection::Egress);
    }

    #[test]
    fn test_constants_are_nonzero() {
        const { assert!(HANDLE_MIN_INGRESS > 0) };
        const { assert!(HANDLE_MIN_EGRESS > 0) };
        const { assert!(HONK_FILTER_HANDLE > 0) };
    }
}
