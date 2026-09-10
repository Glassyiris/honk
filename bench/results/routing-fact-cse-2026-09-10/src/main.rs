#![allow(dead_code)]

use anyhow::{Context, ensure};
use honk_ebpf_common::{DomainRouting, LpmKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

const BASELINE_COMMIT: &str = "d2cf18438debba60d87ce46ba6da68bca6f072b3";
const BASELINE_SOURCE_SHA256: &str =
    "20b09db070e0da3344e17d6a32b6de50023fd4d7d7725af9e7e9add79889efa9";
const BASELINE_METADATA_SHA256: &str =
    "670f0c6ed0a6ec808c1bbfb5a1d901e40e5a9ddf332b85fdcfce4060dfe8808e";
const MAP_FDS: [i32; 6] = [101, 102, 103, 104, 105, 106];

pub mod routing {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct PortRange {
        pub start: u16,
        pub end: u16,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelCondition {
    pub not: bool,
    pub predicate: KernelPredicate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KernelPredicate {
    Domain(u32),
    DestinationIp(u32),
    SourceIp(u32),
    Mac(u32),
    DestinationPort(Vec<routing::PortRange>),
    SourcePort(Vec<routing::PortRange>),
    Protocol(u8),
    IpVersion(u8),
    Dscp(Vec<u8>),
    ProcessName(Vec<Vec<u8>>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelRule {
    pub id: u32,
    pub source: String,
    pub conditions: Vec<KernelCondition>,
    pub outbound: u8,
    pub must: bool,
    pub mark: u32,
}

#[derive(Debug, Clone, Default)]
pub struct RoutingFactMaps {
    pub destination_v4: Vec<(LpmKey, DomainRouting)>,
    pub destination_v6: Vec<(LpmKey, DomainRouting)>,
    pub source_v4: Vec<(LpmKey, DomainRouting)>,
    pub source_v6: Vec<(LpmKey, DomainRouting)>,
    pub mac: Vec<(LpmKey, DomainRouting)>,
}

#[derive(Debug, Clone)]
pub struct RoutingPushPlan {
    pub(crate) rules: Vec<KernelRule>,
    pub(crate) facts: RoutingFactMaps,
    pub(crate) fallback: u8,
    pub(crate) features: u32,
    pub(crate) fingerprint: [u8; 32],
    pub has_domain_rules: bool,
    pub(crate) domain_predicate_count: usize,
}

include!(concat!(env!("OUT_DIR"), "/emitters.rs"));

struct Variant {
    name: &'static str,
    plan: RoutingPushPlan,
}

fn condition(predicate: KernelPredicate) -> KernelCondition {
    KernelCondition {
        not: false,
        predicate,
    }
}

fn not(predicate: KernelPredicate) -> KernelCondition {
    KernelCondition {
        not: true,
        predicate,
    }
}

fn rule(id: u32, conditions: Vec<KernelCondition>) -> KernelRule {
    KernelRule {
        id,
        source: format!("evidence-{id}"),
        conditions,
        outbound: 2 + (id % 32) as u8,
        must: id % 2 == 0,
        mark: 0x1000 + id,
    }
}

fn plan(rules: Vec<KernelRule>) -> RoutingPushPlan {
    RoutingPushPlan {
        rules,
        facts: RoutingFactMaps::default(),
        fallback: 0,
        features: 0,
        fingerprint: [0; 32],
        has_domain_rules: false,
        domain_predicate_count: 0,
    }
}

fn destination_plan(count: u32) -> RoutingPushPlan {
    plan(
        (0..count)
            .map(|id| rule(id, vec![condition(KernelPredicate::DestinationIp(id))]))
            .collect(),
    )
}

fn variants() -> Vec<Variant> {
    let mut variants: Vec<_> = [0, 1, 4, 16, 64, 256]
        .into_iter()
        .map(|count| Variant {
            name: match count {
                0 => "dst-0",
                1 => "dst-1",
                4 => "dst-4",
                16 => "dst-16",
                64 => "dst-64",
                256 => "dst-256",
                _ => unreachable!(),
            },
            plan: destination_plan(count),
        })
        .collect();

    let mut early = destination_plan(16);
    early.rules.insert(
        0,
        KernelRule {
            id: 9000,
            source: "evidence-early-port".into(),
            conditions: vec![condition(KernelPredicate::DestinationPort(vec![
                routing::PortRange {
                    start: 8443,
                    end: 8443,
                },
            ]))],
            outbound: 1,
            must: true,
            mark: 0x6000,
        },
    );
    variants.push(Variant {
        name: "early-dst-16",
        plan: early,
    });

    variants.push(Variant {
        name: "short-circuit-dst",
        plan: plan(vec![
            rule(
                8000,
                vec![
                    condition(KernelPredicate::DestinationPort(vec![
                        routing::PortRange { start: 9, end: 9 },
                    ])),
                    condition(KernelPredicate::DestinationIp(0)),
                ],
            ),
            rule(8001, vec![condition(KernelPredicate::DestinationIp(1))]),
        ]),
    });
    variants.push(Variant {
        name: "post-lookup-fail",
        plan: plan(vec![
            rule(
                8100,
                vec![
                    condition(KernelPredicate::DestinationIp(0)),
                    condition(KernelPredicate::DestinationPort(vec![
                        routing::PortRange { start: 9, end: 9 },
                    ])),
                ],
            ),
            rule(8101, vec![condition(KernelPredicate::DestinationIp(1))]),
        ]),
    });

    let mut mixed = plan(vec![
        rule(
            7001,
            vec![
                condition(KernelPredicate::DestinationIp(0)),
                condition(KernelPredicate::Protocol(2)),
            ],
        ),
        rule(
            7002,
            vec![
                condition(KernelPredicate::SourceIp(0)),
                condition(KernelPredicate::DestinationPort(vec![
                    routing::PortRange { start: 9, end: 9 },
                ])),
            ],
        ),
        rule(
            7003,
            vec![
                condition(KernelPredicate::Mac(0)),
                condition(KernelPredicate::SourcePort(vec![routing::PortRange {
                    start: 9,
                    end: 9,
                }])),
            ],
        ),
        rule(
            7004,
            vec![
                condition(KernelPredicate::Domain(0)),
                condition(KernelPredicate::DestinationIp(1)),
                condition(KernelPredicate::SourceIp(1)),
                condition(KernelPredicate::Mac(1)),
            ],
        ),
        rule(
            7005,
            vec![
                not(KernelPredicate::DestinationIp(2)),
                not(KernelPredicate::SourceIp(2)),
                not(KernelPredicate::Mac(2)),
                not(KernelPredicate::Domain(1)),
            ],
        ),
    ]);
    mixed.features = 3;
    mixed.has_domain_rules = true;
    mixed.domain_predicate_count = 2;
    variants.push(Variant {
        name: "mixed",
        plan: mixed,
    });
    variants
}

fn predicate_json(predicate: &KernelPredicate) -> Value {
    match predicate {
        KernelPredicate::Domain(id) => json!({"kind": "domain", "id": id}),
        KernelPredicate::DestinationIp(id) => json!({"kind": "destination_ip", "id": id}),
        KernelPredicate::SourceIp(id) => json!({"kind": "source_ip", "id": id}),
        KernelPredicate::Mac(id) => json!({"kind": "mac", "id": id}),
        KernelPredicate::DestinationPort(ranges) => json!({
            "kind": "destination_port",
            "ranges": ranges.iter().map(|range| [range.start, range.end]).collect::<Vec<_>>()
        }),
        KernelPredicate::SourcePort(ranges) => json!({
            "kind": "source_port",
            "ranges": ranges.iter().map(|range| [range.start, range.end]).collect::<Vec<_>>()
        }),
        KernelPredicate::Protocol(mask) => json!({"kind": "protocol", "mask": mask}),
        KernelPredicate::IpVersion(mask) => json!({"kind": "ip_version", "mask": mask}),
        KernelPredicate::Dscp(values) => json!({"kind": "dscp", "values": values}),
        KernelPredicate::ProcessName(names) => json!({"kind": "process_name", "names": names}),
    }
}

fn plan_json(plan: &RoutingPushPlan) -> Value {
    json!({
        "fallback": plan.fallback,
        "features": plan.features,
        "has_domain_rules": plan.has_domain_rules,
        "domain_predicate_count": plan.domain_predicate_count,
        "rules": plan.rules.iter().map(|rule| json!({
            "id": rule.id,
            "outbound": rule.outbound,
            "mark": rule.mark,
            "must": rule.must,
            "conditions": rule.conditions.iter().map(|condition| {
                let mut value = predicate_json(&condition.predicate);
                value["not"] = json!(condition.not);
                value
            }).collect::<Vec<_>>()
        })).collect::<Vec<_>>()
    })
}

fn write_bytecode(path: &Path, insns: &[aya_obj::generated::bpf_insn]) -> anyhow::Result<()> {
    let bytes = unsafe {
        std::slice::from_raw_parts(insns.as_ptr().cast::<u8>(), std::mem::size_of_val(insns))
    };
    std::fs::write(path, bytes).with_context(|| format!("write {}", path.display()))
}

fn sha256(path: &Path) -> anyhow::Result<String> {
    use std::fmt::Write;
    let mut hex = String::with_capacity(64);
    for byte in Sha256::digest(std::fs::read(path)?) {
        write!(&mut hex, "{byte:02x}")?;
    }
    Ok(hex)
}

fn main() -> anyhow::Result<()> {
    let output = PathBuf::from(
        std::env::args_os()
            .nth(1)
            .context("usage: honk-routing-fact-cse-evidence OUTPUT_DIRECTORY")?,
    );
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let candidate_source = Path::new(env!("HONK_CODEGEN_PATH"));
    ensure!(
        sha256(&root.join("baseline-codegen.rs"))? == BASELINE_SOURCE_SHA256,
        "frozen baseline emitter changed"
    );
    ensure!(
        sha256(&root.join("baseline.json"))? == BASELINE_METADATA_SHA256,
        "frozen baseline metadata changed"
    );
    let candidate_source_sha256 = sha256(candidate_source)?;
    std::fs::create_dir_all(&output)
        .with_context(|| format!("create {}", output.display()))?;
    let mut manifest_variants = Vec::new();
    for variant in variants() {
        let fds = baseline::RoutingMapFds {
            destination_v4: MAP_FDS[0],
            destination_v6: MAP_FDS[1],
            source_v4: MAP_FDS[2],
            source_v6: MAP_FDS[3],
            mac: MAP_FDS[4],
            domain: MAP_FDS[5],
        };
        let old = baseline::emit_routing_program(&variant.plan, fds)?.insns;
        let fds = candidate::RoutingMapFds {
            destination_v4: MAP_FDS[0],
            destination_v6: MAP_FDS[1],
            source_v4: MAP_FDS[2],
            source_v6: MAP_FDS[3],
            mac: MAP_FDS[4],
            domain: MAP_FDS[5],
        };
        let new = candidate::emit_routing_program(&variant.plan, fds)?.insns;
        let old_name = format!("{}.old.bpf", variant.name);
        let new_name = format!("{}.new.bpf", variant.name);
        write_bytecode(&output.join(&old_name), &old)?;
        write_bytecode(&output.join(&new_name), &new)?;
        manifest_variants.push(json!({
            "name": variant.name,
            "plan": plan_json(&variant.plan),
            "emitters": {
                "old": {
                    "file": old_name,
                    "instruction_slots": old.len(),
                    "map_lookup_call_sites": old.iter().filter(|insn| insn.code == 0x85 && insn.imm == 1).count()
                },
                "new": {
                    "file": new_name,
                    "instruction_slots": new.len(),
                    "map_lookup_call_sites": new.iter().filter(|insn| insn.code == 0x85 && insn.imm == 1).count()
                }
            }
        }));
    }
    let manifest = json!({
        "schema_version": 1,
        "scope": "SCHED_CLS subprogram evidence only; not production root, freplace, publication, or traffic",
        "baseline": {
            "commit": BASELINE_COMMIT,
            "source": "baseline-codegen.rs",
            "source_sha256": BASELINE_SOURCE_SHA256,
            "metadata": "baseline.json",
            "metadata_sha256": BASELINE_METADATA_SHA256
        },
        "candidate": {
            "source": env!("HONK_CODEGEN_PATH"),
            "source_sha256": candidate_source_sha256
        },
        "map_fd_sentinels": {
            "destination_v4": MAP_FDS[0],
            "destination_v6": MAP_FDS[1],
            "source_v4": MAP_FDS[2],
            "source_v6": MAP_FDS[3],
            "mac": MAP_FDS[4],
            "domain": MAP_FDS[5]
        },
        "variants": manifest_variants
    });
    std::fs::write(
        output.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )?;
    Ok(())
}
