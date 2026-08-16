mod handoff;
pub(crate) use handoff::build_tuples_key;
pub(super) use handoff::{TcpFlowKey, TcpFlowPins};

mod context;

pub(super) use context::{ConnectionGuard, ControlPlaneHandle};

mod tcp;

mod udp;

mod routing;

#[cfg(test)]
pub(in crate::control) use routing::{RealityOutcome, domain_reality_outcome};
