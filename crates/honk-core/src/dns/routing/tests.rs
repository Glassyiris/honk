mod request;
mod response;

use honk_config::dns::{DnsRequestRouting, DnsRouting};

use super::DnsRouter;

fn router_from_request(request: DnsRequestRouting) -> DnsRouter {
    DnsRouter::new(&DnsRouting {
        request,
        ..Default::default()
    })
    .expect("test routing must compile")
}
