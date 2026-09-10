use super::*;
use crate::control::routing_matcher::{KernelCondition, KernelPredicate};
use std::time::Instant;
use sha2::{Digest, Sha256};

fn candidate_source_sha256() -> String {
    use std::fmt::Write as _;
    let mut hex = String::with_capacity(64);
    for byte in Sha256::digest(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/control/routing_matcher/codegen.rs"
    ))) {
        write!(&mut hex, "{byte:02x}").unwrap();
    }
    hex
}

#[path = "baseline-codegen.rs"]
mod baseline;

fn install_baseline(backend: &mut RealEbpfBackend, plan: &RoutingPushPlan) {
    let slot_name = ROUTING_SLOT_NAMES[backend.routing_slot as usize];
    let targets = backend.routing_targets(slot_name).unwrap();
    let generation = backend.routing_generation.as_mut().unwrap();
    let code = baseline::emit_routing_program(plan, baseline::RoutingMapFds {
        destination_v4: lpm_fd(&generation._destination_v4),
        destination_v6: lpm_fd(&generation._destination_v6),
        source_v4: lpm_fd(&generation._source_v4),
        source_v6: lpm_fd(&generation._source_v6),
        mac: lpm_fd(&generation._mac), domain: map_fd(&generation.domain),
    }).unwrap();
    let code = crate::control::routing_matcher::codegen::RoutingBytecode {
        insns: code.insns,
        lines: code.lines.into_iter().map(|line| crate::control::routing_matcher::codegen::RoutingSourceLine {
            insn_offset: line.insn_offset, line: line.line, text: line.text,
        }).collect(),
    };
    generation._links.clear();
    let (btf, program) = load_extension(&targets[0], slot_name, &code).unwrap();
    let links = targets.iter().map(|target| attach_extension(&program, target)).collect::<anyhow::Result<Vec<_>>>().unwrap();
    generation._btf = btf;
    generation._program = program;
    generation._links = links;
}

#[test]
#[ignore = "isolated paired root/slot probe; no network hooks"]
fn paired_root_slot() {
    let ids = HashMap::from([("direct".into(), 0), ("block".into(), 1), ("proxy".into(), 2)]);
    let mut baseline_backend = RealEbpfBackend::load_routing_test_fixture(&object()).unwrap();
    let mut candidate_backend = RealEbpfBackend::load_routing_test_fixture(&object()).unwrap();
    let mut rows = Vec::new();
    for count in [0, 1, 4, 16, 64, 256] {
        for early in [false, true] {
            let mut rules = Vec::new();
            if early {
                rules.push(honk_config::routing::RoutingRule {
                    name: "early-port".into(), condition: honk_config::routing::RoutingCondition {
                        port: vec!["443".into()], ..Default::default()
                    }, outbound: honk_config::routing::RoutingOutbound::Simple("block".into()), priority: 0, must: true, mark: 0x6000,
                });
            }
            rules.extend((0..count).map(|index| honk_config::routing::RoutingRule {
                name: format!("fact-{index}"), condition: honk_config::routing::RoutingCondition {
                    ip: vec![format!("192.0.2.{index}"), format!("2001:db8::{index:x}")], ..Default::default()
                }, outbound: honk_config::routing::RoutingOutbound::Simple("proxy".into()), priority: 0, must: index % 2 == 0, mark: 0x1000 + index,
            }));
            let router = Router::new(&rules, "direct").unwrap();
            let plan = RoutingPushPlan::compile(&router, &ids, "direct", DialMode::Ip).unwrap();
            let started = Instant::now();
            baseline_backend.publish_routing_plan(&plan, &[]).unwrap();
            install_baseline(&mut baseline_backend, &plan);
            let baseline_setup_us = started.elapsed().as_micros();
            let started = Instant::now();
            candidate_backend.publish_routing_plan(&plan, &[]).unwrap();
            let candidate_setup_us = started.elapsed().as_micros();
            for family in [4, 6] {
                for position in ["first", "middle", "late", "miss"] {
                    let index = match position { "first" => 0, "middle" => count / 2, "late" => count.saturating_sub(1), _ => 256 };
                    let mut connection = golden::connection();
                    connection.dst_port = if early {443} else {80};
                    connection.dst_ip = if family == 4 {
                        if index == 256 { "203.0.113.1".parse().unwrap() } else { format!("192.0.2.{index}").parse().unwrap() }
                    } else { format!("2001:db8::{index:x}").parse().unwrap() };
                    let value = input(&connection);
                    let expected = if early { RoutingDecision {outbound: 1, mark: 0x6000, must: 1, domain_final: 1, rule_id: 0} }
                        else if index < count { RoutingDecision {outbound: 2, mark: 0x1000+index, must: (index % 2 == 0) as u32, domain_final: 1, rule_id: index} }
                        else { RoutingDecision {outbound: 0, mark: 0, must: 0, domain_final: 1, rule_id: u32::MAX} };
                    for backend in [&mut baseline_backend, &mut candidate_backend] {
                        let observed = backend.run_routing_test(&value).unwrap();
                        assert_eq!(observed.status, 0);
                        assert_eq!(observed.decision, expected);
                    }
                    let packet = [0u8; 64];
                    let mut samples = [Vec::new(), Vec::new()];
                    for round in 0..17 {
                        for which in if round % 2 == 0 {[0,1]} else {[1,0]} {
                            let backend = if which == 0 {&baseline_backend} else {&candidate_backend};
                            let program: &SchedClassifier = backend.bpf().unwrap().program("routing_test").unwrap().try_into().unwrap();
                            let measured = program.test_run(TestRunOptions {data_in: Some(&packet), repeat: 20000, ..Default::default()}).unwrap();
                            if round >= 2 { samples[which].push(measured.duration.as_nanos()); }
                        }
                    }
                    rows.push(serde_json::json!({"count":count,"early":early,"family":family,"position":position,"baseline_ns":samples[0],"candidate_ns":samples[1],"baseline_setup_us_including_candidate_publish":baseline_setup_us,"candidate_publish_us":candidate_setup_us}));
                }
            }
        }
    }
    let output = std::env::var("HONK_FACT_READY_ROOT_RESULTS").unwrap();
    let candidate_source_sha256 = candidate_source_sha256();
    std::fs::write(output, serde_json::to_vec_pretty(&serde_json::json!({"baseline":{"commit":"ac7cf6a5ab6d7c4229a0c6230a6415965d953403","source_sha256":"477f81f42c422783d5a2790b6d98e34372e23a4c51a1777357dfbf1497543d3a","metadata_sha256":"9ff8a368f80f4d5dec99837a489d58e8943234fbf15fa64629c5194971bb09bc"},"candidate":{"source_sha256":candidate_source_sha256},"scope":"real production freplace attached to all four TC targets; timed canonical test classifier includes input copy and result write plus root/slot; NOT packet parsing or live traffic; setup times are not paired loader costs","repeat":20000,"warmup_rounds":2,"samples":rows})).unwrap()).unwrap();
}

#[test]
#[ignore = "isolated real EXT verifier statistics; no network hooks"]
fn mixed_extension_statistics() {
    use aya_obj::generated::bpf_prog_info;
    let mut backend = RealEbpfBackend::load_routing_test_fixture(&object()).unwrap();
    let targets = backend.routing_targets(ROUTING_SLOT_NAMES[0]).unwrap();
    let target = &targets[0];
    let mut rows = Vec::new();
    for count in [1, 4, 16, 64, 256] {
        let rules = (0..count).map(|index| honk_config::routing::RoutingRule {
            name: format!("mixed-{index}"),
            condition: honk_config::routing::RoutingCondition {
                domain: vec![format!("fact-{index}.test")],
                ip: vec![format!("192.0.2.{index}"), format!("2001:db8::{index:x}")],
                source_ip: vec![format!("198.51.100.{index}"), format!("2001:db9::{index:x}")],
                mac: vec![format!("02:00:00:00:00:{index:02x}")],
                ..Default::default()
            },
            outbound: honk_config::routing::RoutingOutbound::Simple("proxy".into()),
            priority: 0, mark: index, must: false,
        }).collect::<Vec<_>>();
        let router = Router::new(&rules, "direct").unwrap();
        let plan = RoutingPushPlan::compile(&router, &outbound_ids(), "direct", DialMode::Domain).unwrap();
        let maps = create_maps(&plan.facts, &[]).unwrap();
        for candidate in [false, true] {
            let code = if candidate {
                crate::control::routing_matcher::codegen::emit_routing_program(&plan, maps.fds()).unwrap()
            } else {
                let fds = maps.fds();
                let old = baseline::emit_routing_program(&plan, baseline::RoutingMapFds {
                    destination_v4: fds.destination_v4, destination_v6: fds.destination_v6,
                    source_v4: fds.source_v4, source_v6: fds.source_v6, mac: fds.mac, domain: fds.domain,
                }).unwrap();
                crate::control::routing_matcher::codegen::RoutingBytecode {
                    insns: old.insns,
                    lines: old.lines.into_iter().map(|line| crate::control::routing_matcher::codegen::RoutingSourceLine {
                        insn_offset: line.insn_offset, line: line.line, text: line.text,
                    }).collect(),
                }
            };
            let mut btf = target.btf.clone();
            let function_id = btf.id_by_type_name_kind(ROUTING_SLOT_NAMES[0], BtfKind::Func).unwrap();
            let lines = line_info(&mut btf, &code).unwrap();
            let btf_fd = load_btf(&btf.to_bytes()).unwrap();
            let functions = [bpf_func_info {insn_off: 0, type_id: function_id}];
            let mut log = vec![0u8; 1 << 20];
            let mut attr: bpf_attr = unsafe {core::mem::zeroed()};
            attr.__bindgen_anon_3.prog_type = bpf_prog_type::BPF_PROG_TYPE_EXT as u32;
            attr.__bindgen_anon_3.insn_cnt = code.insns.len() as u32;
            attr.__bindgen_anon_3.insns = code.insns.as_ptr() as u64;
            attr.__bindgen_anon_3.license = b"GPL\0".as_ptr() as u64;
            attr.__bindgen_anon_3.prog_btf_fd = btf_fd.as_raw_fd() as u32;
            attr.__bindgen_anon_3.func_info_rec_size = size_of::<bpf_func_info>() as u32;
            attr.__bindgen_anon_3.func_info = functions.as_ptr() as u64;
            attr.__bindgen_anon_3.func_info_cnt = 1;
            attr.__bindgen_anon_3.line_info_rec_size = size_of::<bpf_line_info>() as u32;
            attr.__bindgen_anon_3.line_info = lines.as_ptr() as u64;
            attr.__bindgen_anon_3.line_info_cnt = lines.len() as u32;
            attr.__bindgen_anon_3.attach_btf_id = target.function_id;
            attr.__bindgen_anon_3.__bindgen_anon_1.attach_prog_fd = target.fd.as_fd().as_raw_fd() as u32;
            attr.__bindgen_anon_3.log_level = 4;
            attr.__bindgen_anon_3.log_size = log.len() as u32;
            attr.__bindgen_anon_3.log_buf = log.as_mut_ptr() as u64;
            let start = Instant::now();
            let loaded = bpf_fd(bpf_cmd::BPF_PROG_LOAD, &mut attr);
            let load_us = start.elapsed().as_micros();
            let mut row = serde_json::json!({"count_per_category":count,"candidate":candidate,"baseline_commit":"ac7cf6a5ab6d7c4229a0c6230a6415965d953403","baseline_source_sha256":"477f81f42c422783d5a2790b6d98e34372e23a4c51a1777357dfbf1497543d3a","baseline_metadata_sha256":"9ff8a368f80f4d5dec99837a489d58e8943234fbf15fa64629c5194971bb09bc","candidate_source_sha256":candidate_source_sha256(),"static_bytes":code.insns.len() * std::mem::size_of::<aya_obj::generated::bpf_insn>(),"load_us":load_us,"verifier":verifier_text(&log),"metric_note":"static bytes, kernel verifier processing, JIT bytes, and stack are independent budgets; no emitted-size-to-verifier-cost claim"});
            match loaded {
                Ok(program) => {
                    let _links = targets.iter().map(|target| attach_extension(&program, target)).collect::<anyhow::Result<Vec<_>>>().unwrap();
                    let mut info: bpf_prog_info = unsafe {core::mem::zeroed()};
                    let mut query: bpf_attr = unsafe {core::mem::zeroed()};
                    query.info.bpf_fd = program.as_raw_fd() as u32;
                    query.info.info_len = size_of::<bpf_prog_info>() as u32;
                    query.info.info = (&mut info as *mut bpf_prog_info) as u64;
                    bpf_syscall(bpf_cmd::BPF_OBJ_GET_INFO_BY_FD, &mut query).unwrap();
                    row["jit_bytes"] = info.jited_prog_len.into();
                    row["translated_bytes"] = info.xlated_prog_len.into();
                    row["verified_insns"] = info.verified_insns.into();
                    row["targets_attached"] = targets.len().into();
                }
                Err(error) => {row["error"] = error.to_string().into();}
            }
            rows.push(row);
        }
    }
    std::fs::write(std::env::var("HONK_FACT_READY_EXT_RESULTS").unwrap(), serde_json::to_vec_pretty(&rows).unwrap()).unwrap();
    assert!(rows.iter().all(|row| row.get("error").is_none() && row["jit_bytes"].as_u64().unwrap_or(0) != 0));
}
