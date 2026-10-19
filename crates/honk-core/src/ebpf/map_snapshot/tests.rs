use super::*;

const BPF_F_LOCK: u64 = 4;

fn spec(key_len: usize, value_len: usize, elem_flags: u64) -> BatchSpec {
    BatchSpec {
        fd: 17,
        key_len,
        value_len,
        chunk: 64,
        elem_flags,
    }
}

type Entry = (Vec<u8>, Vec<u8>);

fn collect(
    spec: BatchSpec,
    lookup: impl FnMut(&mut BatchAttr) -> Result<(), i32>,
) -> Result<Vec<Entry>, BatchError> {
    let mut entries = Vec::new();
    scan_with(
        spec,
        &mut None,
        lookup,
        |_, _| true,
        |keys, values| {
            entries.extend(
                keys.chunks_exact(spec.key_len)
                    .zip(values.chunks_exact(spec.value_len))
                    .map(|(key, value)| (key.to_vec(), value.to_vec())),
            );
            true
        },
    )?;
    Ok(entries)
}

#[test]
fn batch_attr_matches_kernel_abi() {
    assert_eq!(std::mem::size_of::<BatchAttr>(), 56);
    assert_eq!(std::mem::offset_of!(BatchAttr, in_batch), 0);
    assert_eq!(std::mem::offset_of!(BatchAttr, out_batch), 8);
    assert_eq!(std::mem::offset_of!(BatchAttr, keys), 16);
    assert_eq!(std::mem::offset_of!(BatchAttr, values), 24);
    assert_eq!(std::mem::offset_of!(BatchAttr, count), 32);
    assert_eq!(std::mem::offset_of!(BatchAttr, map_fd), 36);
    assert_eq!(std::mem::offset_of!(BatchAttr, elem_flags), 40);
    assert_eq!(std::mem::offset_of!(BatchAttr, flags), 48);
    assert_eq!(BPF_MAP_LOOKUP_BATCH, 24);
}

#[test]
fn batch_preserves_partial_cursor_and_final_enoent_entries() {
    let mut calls = 0;
    let expected = [
        (vec![0x11; 16], vec![0x22; 8]),
        (vec![0x33; 16], vec![0x44; 8]),
    ];
    let entries = collect(spec(16, 8, BPF_F_LOCK), |attr| {
        assert_eq!((attr.map_fd, attr.elem_flags), (17, BPF_F_LOCK));
        let next = unsafe { std::slice::from_raw_parts_mut(attr.out_batch as *mut u8, 4) };
        assert_eq!(next, &[0; 4]);
        if calls == 0 {
            assert_eq!(attr.in_batch, 0);
            next[..4].copy_from_slice(&9u32.to_ne_bytes());
        } else {
            assert_eq!(calls, 1, "short successful batches must continue to ENOENT");
            let previous = unsafe { std::slice::from_raw_parts(attr.in_batch as *const u8, 4) };
            assert_eq!(previous, &9u32.to_ne_bytes());
        }
        let (key, value) = &expected[calls];
        unsafe {
            std::slice::from_raw_parts_mut(attr.keys as *mut u8, 16).copy_from_slice(key);
            std::slice::from_raw_parts_mut(attr.values as *mut u8, 8).copy_from_slice(value);
        }
        attr.count = 1;
        calls += 1;
        if calls == 1 {
            Ok(())
        } else {
            Err(libc::ENOENT)
        }
    })
    .unwrap();
    assert_eq!(entries.as_slice(), expected.as_slice());
}

#[test]
fn batch_accepts_empty_terminal_and_rejects_invalid_progress() {
    let entries = collect(spec(1, 8, BPF_F_LOCK), |attr| {
        let cursor = unsafe { std::slice::from_raw_parts(attr.out_batch as *const u8, 4) };
        assert_eq!(cursor, &[0; 4]);
        attr.count = 0;
        Err(libc::ENOENT)
    })
    .unwrap();
    assert!(entries.is_empty());
    for (count, terminal) in [(0, false), (65, false), (u32::MAX, true)] {
        let error = collect(spec(16, 8, BPF_F_LOCK), |attr| {
            attr.count = count;
            if terminal { Err(libc::ENOENT) } else { Ok(()) }
        })
        .unwrap_err();
        assert!(matches!(
            error,
            BatchError::InvalidCount { count: seen, terminal: seen_terminal }
                if seen == count as usize && seen_terminal == terminal
        ));
    }
}

#[test]
fn successful_short_batch_is_not_terminal() {
    let mut calls = 0;
    let entries = collect(spec(4, 4, 0), |attr| {
        calls += 1;
        attr.count = 1;
        if calls < 3 { Ok(()) } else { Err(libc::ENOENT) }
    })
    .unwrap();
    assert_eq!((calls, entries.len()), (3, 3));
}

#[test]
fn batch_errors_never_return_partial_or_fallback_success() {
    for elem_flags in [0, BPF_F_LOCK] {
        for errno in [
            libc::EINVAL,
            libc::ENOSYS,
            libc::EOPNOTSUPP,
            libc::EFAULT,
            libc::EPERM,
            libc::EIO,
            libc::ENOSPC,
        ] {
            for after_partial in [false, true] {
                let mut calls = 0;
                let error = collect(spec(16, 8, elem_flags), |attr| {
                    calls += 1;
                    if after_partial && calls == 1 {
                        attr.count = 1;
                        return Ok(());
                    }
                    attr.count = u32::MAX;
                    Err(errno)
                })
                .unwrap_err();
                assert_eq!(calls, if after_partial { 2 } else { 1 });
                assert!(matches!(
                    error,
                    BatchError::Errno { errno: seen, after_progress }
                        if seen == errno && after_progress == after_partial
                ));
            }
        }
    }
}

#[test]
fn capability_rejection_is_only_allowed_before_progress() {
    for after_partial in [false, true] {
        let mut calls = 0;
        let mut seen = Vec::new();
        let completed = scan_with(
            spec(4, 4, 0),
            &mut None,
            |attr| {
                calls += 1;
                attr.count = 1;
                if after_partial && calls == 1 {
                    Ok(())
                } else {
                    Err(libc::EINVAL)
                }
            },
            |result, _| {
                seen.push(result);
                result != Err(libc::EINVAL)
            },
            |_, _| true,
        );
        if after_partial {
            assert!(matches!(
                completed,
                Err(BatchError::Errno {
                    errno: libc::EINVAL,
                    after_progress: true,
                })
            ));
            assert_eq!(seen, [Ok(())]);
        } else {
            assert!(matches!(completed, Ok(false)));
            assert_eq!(seen, [Err(libc::EINVAL)]);
        }
    }
}

#[test]
fn visitor_can_stop_the_scan() {
    let mut calls = 0;
    let completed = scan_with(
        spec(4, 4, 0),
        &mut None,
        |attr| {
            calls += 1;
            attr.count = 1;
            Ok(())
        },
        |_, _| true,
        |_, _| false,
    );
    assert!(matches!(completed, Ok(true)));
    assert_eq!(calls, 1);
}

#[test]
fn terminal_enoent_preserves_partial_count() {
    let spec = BatchSpec {
        chunk: 128,
        ..spec(4, 4, 0)
    };
    for count in [0, 1, 127, 128, 129, 255] {
        let mut returned = 0;
        let completed = scan_with(
            spec,
            &mut None,
            |attr| {
                attr.count = count;
                Err(libc::ENOENT)
            },
            |_, count| {
                *count = (*count).min(spec.chunk as u32);
                true
            },
            |keys, _| {
                returned = keys.len() / spec.key_len;
                true
            },
        )
        .unwrap();
        assert!(completed);
        assert_eq!(returned, (count as usize).min(spec.chunk));
    }
}

#[test]
fn stopped_batch_resumes_at_saved_bucket_and_resets_at_end() {
    let mut cursor = None;
    scan_with(
        spec(4, 4, BPF_F_LOCK),
        &mut cursor,
        |attr| {
            assert_eq!(attr.in_batch, 0);
            unsafe { (attr.out_batch as *mut u32).write_unaligned(17) };
            attr.count = 1;
            Ok(())
        },
        |_, _| true,
        |_, _| false,
    )
    .unwrap();
    assert_eq!(cursor, Some(17u32.to_ne_bytes()));
    scan_with(
        spec(4, 4, BPF_F_LOCK),
        &mut cursor,
        |attr| {
            assert_eq!(
                unsafe { (attr.in_batch as *const u32).read_unaligned() },
                17
            );
            attr.count = 1;
            Err(libc::ENOENT)
        },
        |_, _| true,
        |_, _| true,
    )
    .unwrap();
    assert!(cursor.is_none());
}
