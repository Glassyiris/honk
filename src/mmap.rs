use crate::libc::mmap;

pub struct Mmap {
    pub(crate) ptr: *mut u8,
    len: usize,
}

impl Mmap {
    #[inline]
    pub fn map_umem(length: usize) -> std::io::Result<Self> {
        Self::do_mmap(
            length,
            0,
            mmap::Flags::MAP_PRIVATE | mmap::Flags::MAP_ANONYMOUS,
            -1,
        )
    }

    #[inline]
    pub fn map_ring(
        length: usize,
        offset: u64,
        socket: std::os::fd::RawFd,
    ) -> std::io::Result<Self> {
        Self::do_mmap(
            length,
            offset,
            mmap::Flags::MAP_SHARED | mmap::Flags::MAP_POPULATE,
            socket,
        )
    }

    #[inline]
    fn do_mmap(
        length: usize,
        offset: u64,
        flags: mmap::Flags::Enum,
        file: i32,
    ) -> std::io::Result<Self> {
        // SAFETY: syscalls
        unsafe {
            let base = mmap::mmap(
                std::ptr::null_mut(),
                length,
                mmap::Prot::PROT_READ | mmap::Prot::PROT_WRITE,
                flags,
                file,
                offset as _,
            );
            if base == mmap::MAP_FAILED {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(Self {
                    ptr: base.cast(),
                    len: length,
                })
            }
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }
}

// SAFETY: Safe to send across threads
unsafe impl Send for Mmap {}

impl Drop for Mmap {
    fn drop(&mut self) {
        // SAFETY: syscall, the pointer is validated before we create an Mmap
        unsafe { mmap::munmap(self.ptr.cast(), self.len) };
    }
}
