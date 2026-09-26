//! How a subscription download leaves: straight to its host when its
//! `download_detour` is `direct`, otherwise through the routing rules or the
//! group it names, like every other download honk makes itself.

use honk_config::subscription::Subscription;

#[cfg(feature = "native-api")]
pub(crate) type Routing = crate::download_route::SharedOutbounds;
#[cfg(not(feature = "native-api"))]
pub(crate) type Routing = std::convert::Infallible;

/// The subscription is fetched straight from its host, outside routing.
pub(crate) fn direct(subscription: &Subscription) -> bool {
    resolves_direct(&subscription.download_detour, cfg!(feature = "native-api"))
}

/// Without a routed transport the default keeps the direct fetch; an
/// explicit `routing` or group still fails rather than going direct.
fn resolves_direct(detour: &str, routed_transport: bool) -> bool {
    match detour {
        "direct" => true,
        "" => !routed_transport,
        _ => false,
    }
}

/// The route chosen for a subscription has no node that can carry it, as when
/// the rules send it to a group of the nodes it has not delivered yet.
#[derive(Debug, thiserror::Error)]
#[error(
    "subscription '{subscription}': its download route '{outbound}' has no usable node yet, so it cannot carry this download; set download_detour: direct for this subscription to fetch it outside routing"
)]
pub(crate) struct RouteUnavailable {
    subscription: String,
    outbound: String,
}

/// The provider status code for a failed fetch.
pub(crate) fn failure_code(error: &anyhow::Error) -> &'static str {
    if error.downcast_ref::<RouteUnavailable>().is_some() {
        "route_unavailable"
    } else {
        "fetch_failed"
    }
}

#[cfg(not(feature = "native-api"))]
pub(super) async fn fetch(
    subscription: &Subscription,
    _routing: Option<&Routing>,
) -> anyhow::Result<Vec<u8>> {
    anyhow::bail!(
        "subscription '{}': this build cannot route subscription downloads; set download_detour: direct or leave it empty",
        subscription.name
    )
}

#[cfg(feature = "native-api")]
pub(super) use routed::fetch;

#[cfg(test)]
mod tests;

#[cfg(feature = "native-api")]
mod routed {
    use std::net::{IpAddr, SocketAddr};
    use std::time::Duration;

    use honk_config::subscription::Subscription;
    use tokio::time::{Instant, timeout_at};

    use super::{RouteUnavailable, Routing};
    use crate::download_route::{self, NoUsableNode, Reply};

    const TIMEOUT: Duration = Duration::from_secs(30);

    /// Fetches the subscription through its route. Every redirect hop is
    /// routed again, because its host usually differs.
    pub(in crate::subscription) async fn fetch(
        subscription: &Subscription,
        routing: Option<&Routing>,
    ) -> anyhow::Result<Vec<u8>> {
        let routing = routing.ok_or_else(|| {
            anyhow::anyhow!(
                "subscription '{}': routing is not ready yet",
                subscription.name
            )
        })?;
        let deadline = Instant::now() + TIMEOUT;
        let mut url = reqwest::Url::parse(&subscription.url)?;
        let mut headers = super::super::subscription_request_headers(subscription)?;
        // Userinfo becomes Basic auth unless a configured Authorization wins.
        crate::marked_http::normalize_url(&mut url, &mut headers)?;
        let origin = url.clone();
        let mut redirects = 0;
        loop {
            let reply = get(subscription, routing, &url, &headers, deadline).await?;
            // The direct fetch's rules: follow a redirect status that names
            // a Location, fail on 4xx and 5xx, and take any other body.
            if crate::marked_http::followed_redirect(reply.status)
                && let Some(location) = reply.location
            {
                redirects += 1;
                let mut next = url.join(location.to_str()?)?;
                strip_userinfo(&mut next);
                anyhow::ensure!(
                    redirects <= super::super::MAX_SUBSCRIPTION_REDIRECTS,
                    "subscription redirected too many times"
                );
                if let Some(reason) = super::super::subscription_redirect_error(&origin, &next) {
                    anyhow::bail!(reason);
                }
                super::super::follow_subscription_redirect(&url, &next, &mut headers);
                url = next;
                continue;
            }
            anyhow::ensure!(
                !reply.status.is_client_error() && !reply.status.is_server_error(),
                "subscription server answered HTTP {}",
                reply.status
            );
            return Ok(reply.body.to_vec());
        }
    }

    fn strip_userinfo(url: &mut reqwest::Url) {
        let _ = url.set_username("");
        let _ = url.set_password(None);
    }

    async fn get(
        subscription: &Subscription,
        routing: &Routing,
        url: &reqwest::Url,
        headers: &http::HeaderMap,
        deadline: Instant,
    ) -> anyhow::Result<Reply> {
        let host = url
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("subscription URL has no host"))?;
        let port = url
            .port_or_known_default()
            .ok_or_else(|| anyhow::anyhow!("subscription URL has no port"))?;
        let detour = match subscription.download_detour.as_str() {
            "" | "routing" => None,
            group => Some(group),
        };
        let outbounds = routing.outbounds();
        let decision = timeout_at(
            deadline,
            outbounds.decide(
                detour,
                "subscription.download_detour",
                "subscription download",
                (host, port),
                None,
            ),
        )
        .await
        .map_err(|_| anyhow::anyhow!("subscription download timed out"))?
        .map_err(|error| match error.downcast_ref::<NoUsableNode>() {
            Some(unusable) => anyhow::Error::new(RouteUnavailable {
                subscription: subscription.name.clone(),
                outbound: unusable.outbound.clone(),
            }),
            None => error,
        })?;
        let reply = match decision.route {
            download_route::Route::Block => {
                anyhow::bail!("routing sends the subscription download to 'block'")
            }
            download_route::Route::Direct { .. } => {
                let stream = connect_direct(host, port, deadline).await?;
                download_route::get(
                    stream,
                    url,
                    headers,
                    deadline,
                    super::super::MAX_SUBSCRIPTION_BYTES,
                )
                .await
            }
            download_route::Route::Proxy { node, .. } => {
                let tunnel = timeout_at(deadline, outbounds.tunnel(&node, (host, port)))
                    .await
                    .map_err(|_| anyhow::anyhow!("subscription download timed out"))??;
                let reply = match timeout_at(deadline, tunnel.dial()).await {
                    Err(_) => Err("download_timeout"),
                    Ok(Err(error)) => {
                        tracing::debug!(%error, node = %node.name, "subscription tunnel dial failed");
                        Err("connection_failed")
                    }
                    Ok(Ok(stream)) => {
                        download_route::get(
                            stream,
                            url,
                            headers,
                            deadline,
                            super::super::MAX_SUBSCRIPTION_BYTES,
                        )
                        .await
                    }
                };
                if let Err(error) = tunnel.close().await {
                    tracing::warn!(%error, "subscription download tunnel did not close cleanly");
                }
                reply
            }
        };
        reply.map_err(|stage| match stage {
            "asset_too_large" => anyhow::anyhow!(
                "subscription body exceeds {} bytes",
                super::super::MAX_SUBSCRIPTION_BYTES
            ),
            stage => anyhow::anyhow!("subscription download failed: {stage}"),
        })
    }

    /// Straight to the host, resolved with the bootstrap resolver, over the
    /// configured bypass mark.
    async fn connect_direct(
        host: &str,
        port: u16,
        deadline: Instant,
    ) -> anyhow::Result<tokio::net::TcpStream> {
        let host = host.trim_matches(['[', ']']);
        let addresses = match host.parse::<IpAddr>() {
            Ok(ip) => vec![ip],
            Err(_) => timeout_at(deadline, honk_outbound::bootstrap::resolve(host))
                .await
                .map_err(|_| anyhow::anyhow!("subscription download timed out"))??,
        };
        let mut last = None;
        for ip in addresses {
            match honk_outbound::util::connect_marked_addr(
                SocketAddr::new(ip, port),
                Some(honk_outbound::util::bypass_mark()),
                deadline.saturating_duration_since(Instant::now()),
            )
            .await
            {
                Ok(stream) => return Ok(stream),
                Err(error) => last = Some(error),
            }
        }
        Err(last.map_or_else(
            || anyhow::anyhow!("subscription host '{host}' has no address"),
            anyhow::Error::from,
        ))
    }
}
