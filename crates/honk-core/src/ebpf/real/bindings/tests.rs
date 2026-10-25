use super::*;
use crate::ebpf::interface::Direction::{Egress, Ingress};
use crate::ebpf::interface::TcProgram::{LanEgressL2, LanIngressL2, WanEgressL2, WanIngressL3};

fn binding(index: u32, direction: Direction, program: TcProgram) -> Binding {
    Binding {
        ifindex: NonZeroU32::new(index).unwrap(),
        direction,
        program,
        interface: format!("v{index}"),
    }
}

fn held(binding: &Binding, link_id: u32) -> Held {
    Held {
        key: key_of(binding),
        program: binding.program,
        link_id,
        interface: binding.interface.clone(),
    }
}

fn fd() -> OwnedFd {
    std::fs::File::open("/dev/null").unwrap().into()
}

#[test]
fn diff_keeps_unchanged_keys_and_only_checks_when_verifying() {
    let wanted = [
        binding(2, Ingress, LanIngressL2),
        binding(2, Egress, LanEgressL2),
    ];
    let held = [held(&wanted[0], 10), held(&wanted[1], 11)];
    assert!(diff(&held, &wanted, false).is_empty());
    assert_eq!(
        diff(&held, &wanted, true),
        [
            Step::Check {
                binding: &wanted[0],
                link_id: 10
            },
            Step::Check {
                binding: &wanted[1],
                link_id: 11
            },
        ]
    );
    // A diagnostic name is not the resource key: no relink, and no Check
    // unless verifying, but the new name is reported.
    let mut renamed = wanted.clone();
    renamed[0].interface = "renamed".into();
    assert_eq!(diff(&held, &renamed, false), [Step::Rename(&renamed[0])]);
    assert_eq!(
        diff(&held, &renamed, true),
        [
            Step::Rename(&renamed[0]),
            Step::Check {
                binding: &renamed[0],
                link_id: 10
            },
            Step::Check {
                binding: &renamed[1],
                link_id: 11
            },
        ]
    );
}

#[test]
fn diff_reprograms_instead_of_stacking_and_removes_only_absent_keys() {
    let old = [
        binding(2, Ingress, LanIngressL2),
        binding(2, Egress, LanEgressL2),
        binding(3, Egress, WanEgressL2),
    ];
    let held = [held(&old[0], 10), held(&old[1], 11), held(&old[2], 12)];
    let wanted = [
        binding(2, Ingress, WanIngressL3),
        binding(2, Egress, WanEgressL2),
        binding(4, Ingress, LanIngressL2),
    ];
    assert_eq!(
        diff(&held, &wanted, false),
        [
            Step::Remove(key_of(&old[2])),
            Step::Reprogram {
                to: &wanted[0],
                from: LanIngressL2,
                link_id: 10
            },
            Step::Reprogram {
                to: &wanted[1],
                from: LanEgressL2,
                link_id: 11
            },
            Step::Create(&wanted[2]),
        ]
    );
}

#[test]
fn namespace_identity_is_the_link_id_not_the_program_id() {
    let chain = Chain {
        links: vec![10, 20, 0],
    };
    assert!(chain.contains_link(10));
    assert!(!chain.contains_link(30));
    assert!(
        !chain.contains_link(0),
        "legacy attachment is not an owned link"
    );
}

#[test]
fn commit_replaces_existing_add_and_ignores_missing_removals() {
    let old = binding(2, Ingress, LanIngressL2);
    let other = binding(3, Egress, LanEgressL2);
    let mut owned = vec![(old.clone(), 10, fd()), (other.clone(), 11, fd())];
    let first_fd = owned[0].2.as_raw_fd();
    let updated = binding(2, Ingress, WanIngressL3);
    let commit = BindingCommit {
        add: vec![(updated.clone(), 12, fd())],
        remove: vec![(NonZeroU32::new(99).unwrap(), Egress)],
        reprogram: vec![(other.ifindex, other.direction, WanEgressL2)],
        rename: vec![
            (other.ifindex, other.direction, "p9".into()),
            (NonZeroU32::new(99).unwrap(), Egress, "gone".into()),
        ],
    };
    let closed = commit.apply_to(&mut owned);
    assert_eq!(closed.len(), 1);
    assert_eq!(closed[0].as_raw_fd(), first_fd);
    assert_eq!(owned.len(), 2);
    assert_eq!(owned[0].0, updated);
    assert_eq!(owned[0].1, 12);
    assert_eq!(owned[1].0.program, WanEgressL2);
    assert_eq!(owned[1].0.interface, "p9");
    assert_eq!(owned[1].1, 11, "a rename keeps the link");

    let commit = BindingCommit {
        remove: vec![key_of(&updated)],
        ..BindingCommit::default()
    };
    assert_eq!(commit.apply_to(&mut owned).len(), 1);
    assert_eq!(owned.len(), 1);
    assert_eq!(key_of(&owned[0].0), key_of(&other));
    assert!(BindingCommit::default().is_empty());
}

#[test]
fn target_comparison_rejects_name_framing_master_and_kind_changes_only() {
    let old = LinkSnapshot {
        ifindex: NonZeroU32::new(2).unwrap(),
        name: "v2".into(),
        arphrd: 1,
        flags: 0,
        master: None,
        kind: Some("veth".into()),
        mac: None,
    };
    let mut after = old.clone();
    after.flags = u32::MAX;
    after.mac = Some([2; 6]);
    assert!(same_device(&old, &after));
    for changed in [
        LinkSnapshot {
            name: "new".into(),
            ..old.clone()
        },
        LinkSnapshot {
            arphrd: 512,
            ..old.clone()
        },
        LinkSnapshot {
            master: NonZeroU32::new(3),
            ..old.clone()
        },
        LinkSnapshot {
            kind: None,
            ..old.clone()
        },
    ] {
        assert!(!same_device(&old, &changed));
    }
}
