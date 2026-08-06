//! nftables ruleset management over raw netlink: the `honk_nfqueue` inet
//! table with one base chain (`prerouting`, priority -250 — after defrag
//! (-400), before conntrack (-200)) whose rules queue packets carrying
//! honk's NFQUEUE_PENDING_MARK on managed LAN interfaces to the worker
//! queues.
//!
//! Everything is exchanged inside NFNL batches, so install/uninstall are
//! atomic.  Only objects this module created are ever deleted: rules are
//! removed by the handle recorded at install time, and the chain/table are
//! honk-owned by name.

use std::io;

use crate::netlink;

// NFT_MSG_* (NFNL_SUBSYS_NFTABLES << 8 | type).
const NFT_MSG_NEWTABLE: u16 = 0;
const NFT_MSG_DELTABLE: u16 = 2;
const NFT_MSG_NEWCHAIN: u16 = 3;
const NFT_MSG_DELCHAIN: u16 = 5;
const NFT_MSG_NEWRULE: u16 = 6;
const NFT_MSG_GETRULE: u16 = 7;
const NFT_MSG_DELRULE: u16 = 8;

const NFTA_TABLE_NAME: u16 = 1;
const NFTA_TABLE_FLAGS: u16 = 2;

const NFTA_CHAIN_TABLE: u16 = 1;
const NFTA_CHAIN_NAME: u16 = 3;
const NFTA_CHAIN_HOOK: u16 = 4;
const NFTA_CHAIN_POLICY: u16 = 5;
const NFTA_CHAIN_TYPE: u16 = 7;

const NFTA_HOOK_HNUM: u16 = 1;
const NFTA_HOOK_PRIORITY: u16 = 2;

const NFTA_RULE_TABLE: u16 = 1;
const NFTA_RULE_CHAIN: u16 = 2;
const NFTA_RULE_HANDLE: u16 = 3;
const NFTA_RULE_EXPRESSIONS: u16 = 4;
const NFTA_RULE_USERDATA: u16 = 7;

const NFTA_LIST_ELEM: u16 = 1;
const NFTA_EXPR_NAME: u16 = 1;
const NFTA_EXPR_DATA: u16 = 2;

const NFTA_META_DREG: u16 = 1;
const NFTA_META_KEY: u16 = 2;
const NFT_META_MARK: u32 = 3;
const NFT_META_IIF: u32 = 4;
const NFT_META_L4PROTO: u32 = 16;

const NFTA_CMP_SREG: u16 = 1;
const NFTA_CMP_OP: u16 = 2;
const NFTA_CMP_DATA: u16 = 3;
const NFT_CMP_EQ: u32 = 0;
const NFT_CMP_NEQ: u32 = 1;

const NFTA_DATA_VALUE: u16 = 1;

const NFTA_BITWISE_SREG: u16 = 1;
const NFTA_BITWISE_DREG: u16 = 2;
const NFTA_BITWISE_LEN: u16 = 3;
const NFTA_BITWISE_MASK: u16 = 4;
const NFTA_BITWISE_XOR: u16 = 5;

const NFTA_QUEUE_NUM: u16 = 1;
const NFTA_QUEUE_TOTAL: u16 = 2;
const NFTA_QUEUE_FLAGS: u16 = 3;

const NFT_REG_1: u32 = 1;
const NF_INET_PRE_ROUTING: u32 = 0;
const NF_ACCEPT: u32 = 1;
const IPPROTO_UDP: u32 = 17;

/// Base-chain priority: after defrag (-400), before conntrack (-200), so
/// queued packets arrive reassembled and a verdict that drops a proxied or
/// blocked flow never creates a useless conntrack entry.
pub const CHAIN_PRIORITY: i32 = -250;

pub const TABLE_NAME: &str = "honk_nfqueue";
pub const CHAIN_NAME: &str = "udp_decision";
/// Rule userdata tag: only rules carrying it are recorded and later
/// deleted, so a hand-edited rule in our table can never be swept away by
/// accident.
pub const RULE_TAG: &[u8] = b"honk-nfqueue";

#[derive(Debug, thiserror::Error)]
pub enum RulesError {
    #[error("netlink: {0}")]
    Io(#[from] io::Error),
    #[error("interface '{0}' does not exist")]
    NoSuchInterface(String),
    #[error("expected {expected} queue rules after install, found {found}")]
    VerifyCount { expected: usize, found: usize },
}

pub struct RulesetConfig {
    /// Managed LAN interface names (resolved to ifindex at install).
    pub interfaces: Vec<String>,
    pub queue_base: u16,
    pub workers: u16,
    pub pending_mark: u32,
}

pub struct NftRuleset {
    config: RulesetConfig,
    fd: i32,
    seq: u32,
    rule_handles: Vec<u64>,
}

impl NftRuleset {
    pub fn new(config: RulesetConfig) -> Result<Self, RulesError> {
        Ok(Self {
            config,
            fd: netlink::netlink_socket(false)?,
            seq: 1,
            rule_handles: Vec::new(),
        })
    }

    fn next_seq(&mut self) -> u32 {
        let seq = self.seq;
        self.seq += 1;
        seq
    }

    /// Atomically install table + chain + one queue rule per interface,
    /// then verify by dumping the rules back and recording their handles.
    /// A leftover table from a crashed instance is removed first (it is
    /// honk-owned by name; anything inside it is stale by definition).
    pub fn install(&mut self) -> Result<(), RulesError> {
        self.remove_stale_table()?;

        let mut buf = Vec::with_capacity(4096);
        let seq = self.next_seq();
        batch_begin(&mut buf, seq);
        let msg = self.begin_msg(&mut buf, NFT_MSG_NEWTABLE, seq);
        netlink::put_attr_str(&mut buf, NFTA_TABLE_NAME, TABLE_NAME);
        netlink::put_attr_be32(&mut buf, NFTA_TABLE_FLAGS, 0);
        netlink::seal_msg(&mut buf, msg);

        let msg = self.begin_msg(&mut buf, NFT_MSG_NEWCHAIN, seq);
        netlink::put_attr_str(&mut buf, NFTA_CHAIN_TABLE, TABLE_NAME);
        netlink::put_attr_str(&mut buf, NFTA_CHAIN_NAME, CHAIN_NAME);
        let hook = netlink::put_nested(&mut buf, NFTA_CHAIN_HOOK);
        netlink::put_attr_be32(&mut buf, NFTA_HOOK_HNUM, NF_INET_PRE_ROUTING);
        netlink::put_attr_be32(&mut buf, NFTA_HOOK_PRIORITY, CHAIN_PRIORITY as u32);
        netlink::seal_nested(&mut buf, hook);
        netlink::put_attr_str(&mut buf, NFTA_CHAIN_TYPE, "filter");
        netlink::put_attr_be32(&mut buf, NFTA_CHAIN_POLICY, NF_ACCEPT);
        netlink::seal_msg(&mut buf, msg);

        let mut ifindexes = Vec::new();
        for name in &self.config.interfaces {
            ifindexes.push((name.clone(), ifindex_of(name)?));
        }
        for (_, ifindex) in &ifindexes {
            let msg = self.begin_msg(&mut buf, NFT_MSG_NEWRULE, seq);
            netlink::put_attr_str(&mut buf, NFTA_RULE_TABLE, TABLE_NAME);
            netlink::put_attr_str(&mut buf, NFTA_RULE_CHAIN, CHAIN_NAME);
            let exprs = netlink::put_nested(&mut buf, NFTA_RULE_EXPRESSIONS);
            put_queue_rule_exprs(
                &mut buf,
                self.config.pending_mark,
                *ifindex,
                self.config.queue_base,
                self.config.workers,
            );
            netlink::seal_nested(&mut buf, exprs);
            netlink::put_attr(&mut buf, NFTA_RULE_USERDATA, RULE_TAG);
            netlink::seal_msg(&mut buf, msg);
        }
        batch_end(&mut buf, seq);
        netlink::send_and_ack(self.fd, &buf, seq)?;

        self.rule_handles = self.dump_rule_handles()?;
        if self.rule_handles.len() != ifindexes.len() {
            return Err(RulesError::VerifyCount {
                expected: ifindexes.len(),
                found: self.rule_handles.len(),
            });
        }
        Ok(())
    }

    /// Structural self-check: the recorded rules (by handle) must still be
    /// exactly what the kernel holds for our table.
    pub fn verify(&self) -> Result<(), RulesError> {
        let current = self.dump_rule_handles()?;
        let mut recorded = self.rule_handles.clone();
        let mut live = current;
        recorded.sort_unstable();
        live.sort_unstable();
        if recorded != live {
            return Err(RulesError::VerifyCount {
                expected: recorded.len(),
                found: live.len(),
            });
        }
        Ok(())
    }

    /// Delete exactly what belongs to us: our tagged rules by handle, then
    /// the chain, then the table.  Each object goes in its own batch so an
    /// already-missing piece (external cleanup, earlier crash) cannot roll
    /// back the remaining deletions; foreign objects are never touched.
    pub fn uninstall(&mut self) -> Result<(), RulesError> {
        for handle in self.dump_rule_handles()? {
            let mut buf = Vec::with_capacity(256);
            let seq = self.next_seq();
            batch_begin(&mut buf, seq);
            let msg = self.begin_msg(&mut buf, NFT_MSG_DELRULE, seq);
            netlink::put_attr_str(&mut buf, NFTA_RULE_TABLE, TABLE_NAME);
            netlink::put_attr_str(&mut buf, NFTA_RULE_CHAIN, CHAIN_NAME);
            netlink::put_attr_be64(&mut buf, NFTA_RULE_HANDLE, handle);
            netlink::seal_msg(&mut buf, msg);
            batch_end(&mut buf, seq);
            self.ack_tolerating_enoent(&buf, seq)?;
        }
        let mut buf = Vec::with_capacity(256);
        let seq = self.next_seq();
        batch_begin(&mut buf, seq);
        let msg = self.begin_msg(&mut buf, NFT_MSG_DELCHAIN, seq);
        netlink::put_attr_str(&mut buf, NFTA_CHAIN_TABLE, TABLE_NAME);
        netlink::put_attr_str(&mut buf, NFTA_CHAIN_NAME, CHAIN_NAME);
        netlink::seal_msg(&mut buf, msg);
        let msg = self.begin_msg(&mut buf, NFT_MSG_DELTABLE, seq);
        netlink::put_attr_str(&mut buf, NFTA_TABLE_NAME, TABLE_NAME);
        netlink::seal_msg(&mut buf, msg);
        batch_end(&mut buf, seq);
        self.ack_tolerating_enoent(&buf, seq)?;
        Ok(())
    }

    fn ack_tolerating_enoent(&self, buf: &[u8], seq: u32) -> Result<(), RulesError> {
        match netlink::send_and_ack(self.fd, buf, seq) {
            Ok(()) => Ok(()),
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /// Best-effort removal of a stale honk table (crash recovery).  All
    /// inside the honk-owned namespace; user tables are never inspected.
    fn remove_stale_table(&mut self) -> Result<(), RulesError> {
        self.uninstall()
    }

    /// Handles of all our tagged rules currently in the kernel.
    fn dump_rule_handles(&self) -> Result<Vec<u64>, RulesError> {
        let mut buf = Vec::with_capacity(128);
        let seq = self.seq;
        let start = netlink::put_msg_header(
            &mut buf,
            (netlink::NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_GETRULE,
            netlink::NLM_F_REQUEST | netlink::NLM_F_DUMP,
            seq,
            netlink::NFPROTO_INET,
            netlink::NFNL_SUBSYS_NFTABLES,
        );
        netlink::put_attr_str(&mut buf, NFTA_RULE_TABLE, TABLE_NAME);
        netlink::seal_msg(&mut buf, start);
        netlink::send(self.fd, &buf)?;

        let mut handles = Vec::new();
        let mut rbuf = vec![0u8; 65536];
        loop {
            let n = netlink::recv(self.fd, &mut rbuf)?;
            for msg in netlink::split_messages(&rbuf[..n]) {
                if msg.seq != seq {
                    continue;
                }
                match msg.msg_type as u32 {
                    t if t == netlink::NLMSG_DONE as u32 => return Ok(handles),
                    t if t == netlink::NLMSG_ERROR as u32 => {
                        let code = netlink::parse_error(msg.body).unwrap_or(-(libc::EIO));
                        if code == 0 {
                            return Ok(handles);
                        }
                        // Table absent: no rules.
                        if -code == libc::ENOENT {
                            return Ok(handles);
                        }
                        return Err(io::Error::from_raw_os_error(-code).into());
                    }
                    t if t
                        == ((netlink::NFNL_SUBSYS_NFTABLES as u32) << 8)
                            | NFT_MSG_NEWRULE as u32 =>
                    {
                        if let Some(handle) = parse_rule_handle(msg.body) {
                            handles.push(handle);
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    fn begin_msg(&self, buf: &mut Vec<u8>, msg_type: u16, seq: u32) -> usize {
        let mut flags = netlink::NLM_F_REQUEST;
        if matches!(
            msg_type,
            NFT_MSG_NEWTABLE | NFT_MSG_NEWCHAIN | NFT_MSG_NEWRULE
        ) {
            flags |= netlink::NLM_F_CREATE;
        }
        netlink::put_msg_header(
            buf,
            (netlink::NFNL_SUBSYS_NFTABLES << 8) | msg_type,
            flags,
            seq,
            netlink::NFPROTO_INET,
            netlink::NFNL_SUBSYS_NFTABLES,
        )
    }
}

impl Drop for NftRuleset {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

fn batch_begin(buf: &mut Vec<u8>, seq: u32) {
    let start = netlink::put_msg_header(
        buf,
        netlink::NFNL_MSG_BATCH_BEGIN,
        netlink::NLM_F_REQUEST,
        seq,
        0,
        netlink::NFNL_BATCH_RES_ID,
    );
    netlink::seal_msg(buf, start);
}

fn batch_end(buf: &mut Vec<u8>, seq: u32) {
    let start = netlink::put_msg_header(
        buf,
        netlink::NFNL_MSG_BATCH_END,
        netlink::NLM_F_REQUEST | netlink::NLM_F_ACK,
        seq,
        0,
        netlink::NFNL_BATCH_RES_ID,
    );
    netlink::seal_msg(buf, start);
}

fn ifindex_of(name: &str) -> Result<u32, RulesError> {
    let cname =
        std::ffi::CString::new(name).map_err(|_| RulesError::NoSuchInterface(name.into()))?;
    let index = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if index == 0 {
        return Err(RulesError::NoSuchInterface(name.into()));
    }
    Ok(index)
}

/// `meta mark & pending_mark != 0  iif <ifindex>  meta l4proto udp
/// queue to base..base+workers-1` — the queue expression without
/// CPU_FANOUT distributes by the kernel flow hash, pinning a flow's
/// packets to one worker.
fn put_queue_rule_exprs(buf: &mut Vec<u8>, pending_mark: u32, ifindex: u32, base: u16, total: u16) {
    put_meta_load(buf, NFT_META_MARK);
    put_bitwise_mask(buf, pending_mark);
    put_cmp_neq_zero(buf);
    put_meta_load(buf, NFT_META_IIF);
    put_cmp_eq_u32(buf, ifindex);
    put_meta_load(buf, NFT_META_L4PROTO);
    put_cmp_eq_u8(buf, IPPROTO_UDP as u8);
    put_queue(buf, base, total);
}

fn put_expr(buf: &mut Vec<u8>, name: &str, data: impl FnOnce(&mut Vec<u8>)) {
    let elem = netlink::put_nested(buf, NFTA_LIST_ELEM);
    netlink::put_attr_str(buf, NFTA_EXPR_NAME, name);
    let expr_data = netlink::put_nested(buf, NFTA_EXPR_DATA);
    data(buf);
    netlink::seal_nested(buf, expr_data);
    netlink::seal_nested(buf, elem);
}

fn put_meta_load(buf: &mut Vec<u8>, key: u32) {
    put_expr(buf, "meta", |b| {
        netlink::put_attr_be32(b, NFTA_META_DREG, NFT_REG_1);
        netlink::put_attr_be32(b, NFTA_META_KEY, key);
    });
}

fn put_bitwise_mask(buf: &mut Vec<u8>, mask: u32) {
    put_expr(buf, "bitwise", |b| {
        netlink::put_attr_be32(b, NFTA_BITWISE_SREG, NFT_REG_1);
        netlink::put_attr_be32(b, NFTA_BITWISE_DREG, NFT_REG_1);
        netlink::put_attr_be32(b, NFTA_BITWISE_LEN, 4);
        let mask_attr = netlink::put_nested(b, NFTA_BITWISE_MASK);
        netlink::put_attr(b, NFTA_DATA_VALUE, &mask.to_ne_bytes());
        netlink::seal_nested(b, mask_attr);
        let xor_attr = netlink::put_nested(b, NFTA_BITWISE_XOR);
        netlink::put_attr(b, NFTA_DATA_VALUE, &0u32.to_ne_bytes());
        netlink::seal_nested(b, xor_attr);
    });
}

fn put_cmp_neq_zero(buf: &mut Vec<u8>) {
    put_expr(buf, "cmp", |b| {
        netlink::put_attr_be32(b, NFTA_CMP_SREG, NFT_REG_1);
        netlink::put_attr_be32(b, NFTA_CMP_OP, NFT_CMP_NEQ);
        let data = netlink::put_nested(b, NFTA_CMP_DATA);
        netlink::put_attr(b, NFTA_DATA_VALUE, &0u32.to_ne_bytes());
        netlink::seal_nested(b, data);
    });
}

fn put_cmp_eq_u32(buf: &mut Vec<u8>, value: u32) {
    put_expr(buf, "cmp", |b| {
        netlink::put_attr_be32(b, NFTA_CMP_SREG, NFT_REG_1);
        netlink::put_attr_be32(b, NFTA_CMP_OP, NFT_CMP_EQ);
        let data = netlink::put_nested(b, NFTA_CMP_DATA);
        netlink::put_attr(b, NFTA_DATA_VALUE, &value.to_ne_bytes());
        netlink::seal_nested(b, data);
    });
}

fn put_cmp_eq_u8(buf: &mut Vec<u8>, value: u8) {
    put_expr(buf, "cmp", |b| {
        netlink::put_attr_be32(b, NFTA_CMP_SREG, NFT_REG_1);
        netlink::put_attr_be32(b, NFTA_CMP_OP, NFT_CMP_EQ);
        let data = netlink::put_nested(b, NFTA_CMP_DATA);
        netlink::put_attr(b, NFTA_DATA_VALUE, &[value]);
        netlink::seal_nested(b, data);
    });
}

fn put_queue(buf: &mut Vec<u8>, base: u16, total: u16) {
    put_expr(buf, "queue", |b| {
        netlink::put_attr_be16(b, NFTA_QUEUE_NUM, base);
        netlink::put_attr_be16(b, NFTA_QUEUE_TOTAL, total);
        netlink::put_attr_be16(b, NFTA_QUEUE_FLAGS, 0);
    });
}

/// Extract the handle of a dumped NEWRULE message that carries our tag;
/// foreign rules (no userdata match) return None.
fn parse_rule_handle(body: &[u8]) -> Option<u64> {
    if body.len() < netlink::NFGENMSG_LEN {
        return None;
    }
    let mut handle = None;
    let mut tagged = false;
    for attr in netlink::attrs(&body[netlink::NFGENMSG_LEN..]) {
        match attr.attr_type {
            NFTA_RULE_HANDLE if attr.payload.len() >= 8 => {
                handle = Some(u64::from_be_bytes(attr.payload[..8].try_into().ok()?));
            }
            NFTA_RULE_USERDATA => tagged = attr.payload == RULE_TAG,
            _ => {}
        }
    }
    if tagged { handle } else { None }
}
