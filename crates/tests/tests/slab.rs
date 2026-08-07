use xdp::slab::Slab as _;

xdp::slab!(TestSlab, u8);

fn umem(frame_count: u32, head_room: u32) -> xdp::Umem {
    use xdp::umem;

    umem::Umem::map(
        umem::UmemCfgBuilder {
            frame_size: umem::FrameSize::TwoK,
            head_room,
            frame_count,
            ..Default::default()
        }
        .build()
        .unwrap(),
    )
    .unwrap()
}

#[test]
fn edge_conditions() {
    const CAP: usize = 64;

    let mut ss = TestSlab::<CAP>::new();
    let mut umem = umem(80, 0);

    assert!(ss.is_empty());
    assert_eq!(ss.available(), CAP);
    assert_eq!(ss.len(), 0);

    for _ in 0..CAP {
        // SAFETY: every packet is drained before the UMEM is dropped.
        let packet = unsafe { umem.alloc() }.unwrap().unwrap();
        assert!(ss.push_front(packet).is_none());
    }

    assert!(!ss.is_empty());
    assert_eq!(ss.available(), 0);
    assert_eq!(ss.len(), CAP);

    // SAFETY: the packet remains within this test's UMEM lifetime.
    let over = unsafe { umem.alloc() }.unwrap().unwrap();
    let over = ss.push_front(over).unwrap();

    let back = ss.pop_back().unwrap();
    assert_eq!(ss.available(), 1);
    assert_eq!(ss.len(), CAP - 1);
    assert!(ss.push_front(over).is_none());

    drop(back);

    while let Some(packet) = ss.pop_back() {
        drop(packet);
    }

    assert!(ss.is_empty());
    assert_eq!(ss.available(), CAP);
    assert_eq!(ss.len(), 0);

    for i in 0..CAP {
        // SAFETY: every packet is drained before the UMEM is dropped.
        let mut packet = unsafe { umem.alloc() }.unwrap().unwrap();
        packet.insert(0, &[i as u8]).unwrap();
        assert!(ss.push_front(packet).is_none());
    }

    assert!(!ss.is_empty());
    assert_eq!(ss.available(), 0);
    assert_eq!(ss.len(), CAP);

    for _ in 0..9 {
        for _ in 0..CAP {
            let p = ss.pop_back().unwrap();
            assert_eq!(ss.len(), CAP - 1);
            assert!(ss.push_front(p).is_none());
        }
    }

    assert_eq!(ss.len(), CAP);

    for i in 0..CAP {
        let p = ss.pop_back().unwrap();
        assert_eq!(&p[0..1], &[i as u8]);
        if i % 2 == 1 {
            assert!(ss.push_front(p).is_none());
        } else {
            drop(p);
        }
    }

    assert_eq!(ss.len(), CAP >> 1);

    while let Some(packet) = ss.pop_back() {
        drop(packet);
    }
    assert_eq!(umem.outstanding(), 0);
}
