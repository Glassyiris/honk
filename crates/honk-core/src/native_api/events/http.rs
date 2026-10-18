//! HTTP negotiation, request parsing and responses for event streams.

use axum::{
    body::Body,
    extract::Request,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};

use super::{Filter, KINDS, Kind, Subscription};
use crate::native_api::{
    ApiError, ErrorCode, NativeState, error, parse_query, settings::Demand, types::RequestId,
};

fn invalid(id: &RequestId) -> ApiError {
    error(
        StatusCode::BAD_REQUEST,
        ErrorCode::InvalidRequest,
        "Invalid event stream request",
        id,
    )
}

pub(super) fn request_options(
    request: &Request,
    id: &RequestId,
) -> Result<(Filter, Option<String>, Demand), ApiError> {
    let values = parse_query(request.uri(), &["kinds", "flow_id"], id)?;
    let kinds = if let Some(kinds) = values.get("kinds") {
        let mut mask = 0;
        for kind in kinds.split(',') {
            let bit = Kind::parse(kind).ok_or_else(|| invalid(id))?.bit();
            if mask & bit != 0 {
                return Err(invalid(id));
            }
            mask |= bit;
        }
        mask
    } else {
        (1 << KINDS.len()) - 1
    };
    let flow_id = values.get("flow_id").cloned();
    if flow_id.as_ref().is_some_and(|flow_id| {
        flow_id.is_empty() || flow_id.len() > 256 || flow_id.chars().any(char::is_control)
    }) || !accepts_events(request.headers())
    {
        return Err(invalid(id));
    }
    let flow_demand = kinds & (Kind::FlowUpdated.bit() | Kind::FlowGap.bit()) != 0
        && (values.contains_key("kinds")
            || flow_id.as_ref().is_some_and(|id| !id.trim().is_empty()));
    Ok((
        Filter::new(kinds, flow_id),
        request_cursor(request, id)?,
        if flow_demand {
            Demand::FLOWS
        } else {
            Demand::NONE
        },
    ))
}

pub(in crate::native_api) fn request_cursor(
    request: &Request,
    id: &RequestId,
) -> Result<Option<String>, ApiError> {
    if !accepts_events(request.headers()) {
        return Err(invalid(id));
    }
    let mut cursors = request.headers().get_all("last-event-id").iter();
    let cursor = cursors
        .next()
        .map(|value| value.to_str().map(str::to_owned).map_err(|_| invalid(id)))
        .transpose()?;
    if cursors.next().is_some() || cursor.as_ref().is_some_and(String::is_empty) {
        return Err(invalid(id));
    }
    Ok(cursor)
}

fn accepts_events(headers: &HeaderMap) -> bool {
    if !headers.contains_key(header::ACCEPT) {
        return true;
    }
    let mut best = None;
    for value in headers.get_all(header::ACCEPT) {
        let Ok(value) = value.to_str() else {
            return false;
        };
        for range in value.split(',') {
            let mut parts = range.trim().split(';');
            let media = parts.next().unwrap_or_default().trim();
            let Some((kind, subtype)) = media.split_once('/') else {
                return false;
            };
            if !token(kind) || !token(subtype) || (kind == "*" && subtype != "*") {
                return false;
            }
            let mut specificity = if media.eq_ignore_ascii_case("text/event-stream") {
                Some(2)
            } else if media.eq_ignore_ascii_case("text/*") {
                Some(1)
            } else if media == "*/*" {
                Some(0)
            } else {
                None
            };
            let mut quality = 1000;
            let mut seen_quality = false;
            for parameter in parts {
                let Some((name, value)) = parameter.trim().split_once('=') else {
                    return false;
                };
                let (name, value) = (name.trim(), value.trim());
                if name.eq_ignore_ascii_case("q") {
                    let Some(parsed) = quality_value(value) else {
                        return false;
                    };
                    if seen_quality {
                        return false;
                    }
                    seen_quality = true;
                    quality = parsed;
                } else {
                    let value = value
                        .strip_prefix('"')
                        .and_then(|v| v.strip_suffix('"'))
                        .unwrap_or(value);
                    if !token(name) || !token(value) {
                        return false;
                    }
                    if !name.eq_ignore_ascii_case("charset") || !value.eq_ignore_ascii_case("utf-8")
                    {
                        specificity = None;
                    }
                }
            }
            if let Some(specificity) = specificity
                && best.is_none_or(|(rank, q)| {
                    specificity > rank || (specificity == rank && quality > q)
                })
            {
                best = Some((specificity, quality));
            }
        }
    }
    best.is_some_and(|(_, quality)| quality > 0)
}

fn token(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
}

fn quality_value(value: &str) -> Option<u16> {
    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
    if !matches!(whole, "0" | "1")
        || fraction.len() > 3
        || !fraction.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let fraction = fraction
        .bytes()
        .fold(0u16, |value, byte| value * 10 + u16::from(byte - b'0'))
        * 10u16.pow(3 - fraction.len() as u32);
    match whole {
        "0" => Some(fraction),
        "1" if fraction == 0 => Some(1000),
        _ => None,
    }
}

pub(in crate::native_api) async fn serve(
    state: &NativeState,
    request: Request,
    id: &RequestId,
) -> Result<Response, ApiError> {
    let (filter, cursor, demand) = request_options(&request, id)?;
    let admit = || {
        state
            .observation
            .events
            .subscribe(filter, cursor.as_deref(), id)
    };
    let subscription = if request.method() == axum::http::Method::GET {
        state
            .observation
            .settings
            .subscribe(&state.observation, demand, admit)?
    } else {
        admit()?
    };
    Ok(stream_response(subscription))
}

pub(in crate::native_api) fn stream_response(subscription: Subscription) -> Response {
    (
        [
            (header::CONTENT_TYPE, "text/event-stream"),
            (header::CACHE_CONTROL, "no-store"),
            (
                header::HeaderName::from_static("x-content-type-options"),
                "nosniff",
            ),
            (header::HeaderName::from_static("x-accel-buffering"), "no"),
        ],
        Body::from_stream(subscription),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::super::request_id;
    use super::*;
    #[test]
    fn request_validation_rejects_ambiguous_filters_headers_and_accept() {
        for uri in [
            "/api/v1/events?unknown=1",
            "/api/v1/events?kinds=flow.updated&kinds=flow.gap",
            "/api/v1/events?kinds=flow.updated,flow.updated",
            "/api/v1/events?kinds=flow.updated,unknown",
            "/api/v1/events?kinds=",
            "/api/v1/events?flow_id=",
        ] {
            let request = Request::builder().uri(uri).body(Body::empty()).unwrap();
            assert_eq!(
                request_options(&request, &request_id())
                    .err()
                    .unwrap()
                    .into_response()
                    .status(),
                StatusCode::BAD_REQUEST
            );
        }
        for accept in [
            "application/json",
            "text/event-stream;q=0, */*;q=1",
            "invalid",
            "text/event-stream;q=NaN",
            "text/event-stream;q=1e0",
            "text/event-stream;q=0.0001",
            "text/event-stream;q=1.001",
            "text/event-stream;q=1;q=0",
            "te xt/event-stream",
        ] {
            let request = Request::builder()
                .header(header::ACCEPT, accept)
                .body(Body::empty())
                .unwrap();
            assert!(request_options(&request, &request_id()).is_err());
        }
        for accept in [
            "text/event-stream",
            "*/*",
            "application/json, text/event-stream;q=0.5",
            "text/event-stream;charset=utf-8",
            "text/event-stream;charset=\"utf-8\";q=1.000",
        ] {
            let request = Request::builder()
                .header(header::ACCEPT, accept)
                .body(Body::empty())
                .unwrap();
            assert!(request_options(&request, &request_id()).is_ok());
        }
        let request = Request::builder()
            .header("last-event-id", "first")
            .header("last-event-id", "second")
            .body(Body::empty())
            .unwrap();
        assert!(request_options(&request, &request_id()).is_err());
        let first = Request::builder()
            .uri("/api/v1/events?kinds=flow.updated,flow.gap")
            .body(Body::empty())
            .unwrap();
        let second = Request::builder()
            .uri("/api/v1/events?kinds=flow.gap,flow.updated")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            request_options(&first, &request_id()).unwrap().0.binding,
            request_options(&second, &request_id()).unwrap().0.binding
        );
    }
}
