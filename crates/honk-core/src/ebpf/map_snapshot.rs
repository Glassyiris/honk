//! Raw `BPF_MAP_LOOKUP_BATCH` traversal shared by the engine and the CLI toolbox.

use std::io;
use std::os::fd::RawFd;

const BPF_MAP_LOOKUP_BATCH: libc::c_long = 24;

#[repr(C)]
#[derive(Default)]
struct BatchAttr {
    in_batch: u64,
    out_batch: u64,
    keys: u64,
    values: u64,
    count: u32,
    map_fd: u32,
    elem_flags: u64,
    flags: u64,
}

#[derive(Clone, Copy)]
pub struct BatchSpec {
    pub fd: RawFd,
    pub key_len: usize,
    pub value_len: usize,
    pub chunk: usize,
    pub elem_flags: u64,
}

#[derive(Debug)]
pub enum BatchError {
    Errno { errno: i32, after_progress: bool },
    InvalidCount { count: usize, terminal: bool },
}

/// # Safety
///
/// The FD must remain an open hash-family map whose batch key/value strides
/// match `spec.key_len`/`spec.value_len`. `spec.chunk` must fit `u32`, and both
/// buffer-size products must fit `usize`.
pub unsafe fn scan(
    spec: BatchSpec,
    cursor: &mut Option<[u8; 4]>,
    adapt_result: impl FnMut(Result<(), i32>, &mut u32) -> bool,
    visit: impl FnMut(&[u8], &[u8]) -> bool,
) -> Result<bool, BatchError> {
    scan_with(spec, cursor, lookup_batch, adapt_result, visit)
}

fn lookup_batch(attr: &mut BatchAttr) -> Result<(), i32> {
    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_MAP_LOOKUP_BATCH,
            attr as *mut BatchAttr,
            std::mem::size_of::<BatchAttr>() as u32,
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO))
    } else {
        Ok(())
    }
}

fn scan_with(
    spec: BatchSpec,
    cursor: &mut Option<[u8; 4]>,
    mut lookup: impl FnMut(&mut BatchAttr) -> Result<(), i32>,
    mut adapt_result: impl FnMut(Result<(), i32>, &mut u32) -> bool,
    mut visit: impl FnMut(&[u8], &[u8]) -> bool,
) -> Result<bool, BatchError> {
    let BatchSpec {
        fd,
        key_len,
        value_len,
        chunk,
        elem_flags,
    } = spec;
    let mut keys = vec![0u8; key_len * chunk];
    let mut values = vec![0u8; value_len * chunk];
    // Hash maps return a four-byte opaque bucket cursor, not a key.
    let mut previous = cursor.unwrap_or_default();
    let mut next = [0u8; 4];
    let mut has_previous = cursor.is_some();
    loop {
        let mut attr = BatchAttr {
            in_batch: if has_previous {
                previous.as_ptr() as u64
            } else {
                0
            },
            out_batch: next.as_mut_ptr() as u64,
            keys: keys.as_mut_ptr() as u64,
            values: values.as_mut_ptr() as u64,
            count: chunk as u32,
            map_fd: fd as u32,
            elem_flags,
            ..Default::default()
        };
        let result = lookup(&mut attr);
        if let Err(errno) = result
            && has_previous
            && errno != libc::ENOENT
        {
            return Err(BatchError::Errno {
                errno,
                after_progress: true,
            });
        }
        if !adapt_result(result, &mut attr.count) {
            return Ok(false);
        }
        let terminal = match result {
            Ok(()) => false,
            Err(libc::ENOENT) => true,
            Err(errno) => {
                return Err(BatchError::Errno {
                    errno,
                    after_progress: false,
                });
            }
        };
        let count = attr.count as usize;
        if count > chunk || (count == 0 && !terminal) {
            return Err(BatchError::InvalidCount { count, terminal });
        }
        *cursor = if terminal { None } else { Some(next) };
        if count > 0 && !visit(&keys[..count * key_len], &values[..count * value_len]) {
            return Ok(true);
        }
        // A successful batch may be short; only ENOENT marks the final batch.
        if terminal {
            return Ok(true);
        }
        std::mem::swap(&mut previous, &mut next);
        next.fill(0);
        has_previous = true;
    }
}

#[cfg(test)]
mod tests;
