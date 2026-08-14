use super::udp_dial::{UdpPrepare, UdpStaggerCallbacks, prepare_udp_plan};
use super::*;
use crate::control::udp_endpoint::{UdpEndpoint, UdpInitLease};
use crate::group::{SelectionNetwork, SelectionPlanMode};
use honk_config::types::NodeProtocol;
use std::collections::{HashMap, HashSet};

fn connection_chains(mut selection_chain: Vec<String>, node_name: &str) -> Vec<String> {
    if selection_chain.last().map(String::as_str) != Some(node_name) {
        selection_chain.push(node_name.to_owned());
    }
    selection_chain.reverse();
    selection_chain
}

mod handoff;
use handoff::HandoffResult;
pub(crate) use handoff::build_tuples_key;
pub(super) use handoff::{TcpFlowKey, TcpFlowPins};

mod context;

pub(super) use context::{ConnectionGuard, ControlPlaneHandle};

mod tcp;

mod udp;

mod flow;

#[cfg(test)]
pub(in crate::control) use flow::{RealityOutcome, domain_reality_outcome};
