use super::udp_dial::{UdpPrepare, UdpStaggerCallbacks, prepare_udp_plan};
use super::*;
use crate::control::udp_endpoint::{UdpEndpoint, UdpInitLease};
use crate::group::{SelectionNetwork, SelectionPlanMode};
use honk_config::types::NodeProtocol;
use std::collections::{HashMap, HashSet};

const COLD_URLTEST_STAGGER: Duration = Duration::from_millis(200);

/// Wait until this candidate's absolute cold-URLTest release offset. The
/// first candidate starts immediately; sleeping candidates have not acquired
/// a dial permit and are cancelled with their enclosing `JoinSet`.
async fn wait_for_cold_urltest_release(index: usize) {
    if index != 0 {
        tokio::time::sleep(COLD_URLTEST_STAGGER.saturating_mul(index as u32)).await;
    }
}
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

mod flow;

#[cfg(test)]
pub(in crate::control) use flow::{RealityOutcome, domain_reality_outcome};
