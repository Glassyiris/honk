#![no_std]
#![no_main]

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

pub mod cgroup;
pub mod compat;
pub mod contrack;
pub mod egress;
pub mod errno;
pub mod event;
pub mod ingress;
pub mod log_shim;
pub mod maps;
pub mod outbound;
pub mod route;
pub mod routing;
pub mod sk_lookup;
pub mod stats;
pub mod transport;
