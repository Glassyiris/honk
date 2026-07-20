use aya_ebpf::bindings::bpf_sock;
use aya_ebpf::helpers::bpf_sk_fullsock;

#[inline(always)]
pub fn bpf_sock_is_dae_socket(sock: *const bpf_sock) -> bool {
    if sock.is_null() {
        return false;
    }

    let param = crate::maps::PARAM.load();

    let fullsock = unsafe { bpf_sk_fullsock(sock as *mut bpf_sock) };
    if fullsock.is_null() {
        return false;
    }
    unsafe { (*fullsock).mark == param.dae_socket_mark }
}
