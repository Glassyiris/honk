//! Checks every `/api` response the suite receives against the OpenAPI
//! contract the embedded doona build was generated from, so handler drift fails CI.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};

use jsonschema::{Draft, Registry, Validator};
use reqwest::header::{CONTENT_TYPE, HeaderName, HeaderValue};
use reqwest::{Client, IntoUrl, Method, RequestBuilder, Response, Url};
use serde_json::Value;

// daeuniverse/api-standardize 1fb08ad (sha256 104e871b...), the bundle doona
// 0.1.0-beta.10 was generated from; refresh it with the doona release honk ships.
const CONTRACT: &str = include_str!("../fixtures/native_api_openapi.yaml");
const CONTRACT_URL: &str = "https://contract.honk.invalid/openapi.json";

/// Responses honk sends that the contract does not describe yet, awaiting an
/// owner decision: (method, path template or raw path, status, reason).
const KNOWN_DRIFT: &[(&str, &str, u16, &str)] = &[];

static DOCUMENT: LazyLock<Value> = LazyLock::new(|| serde_yaml::from_str(CONTRACT).unwrap());

static REGISTRY: LazyLock<Registry<'static>> = LazyLock::new(|| {
    Registry::new()
        .add(CONTRACT_URL, DOCUMENT.clone())
        .unwrap()
        .prepare()
        .unwrap()
});

static VALIDATORS: LazyLock<Mutex<HashMap<String, Arc<Validator>>>> = LazyLock::new(Mutex::default);

/// `TestApp`'s client: identical to reqwest's, except that `send` checks the response.
pub(super) struct ContractClient(pub(super) Client);

impl ContractClient {
    pub(super) fn get(&self, url: impl IntoUrl) -> ContractRequest {
        ContractRequest(self.0.get(url))
    }

    pub(super) fn head(&self, url: impl IntoUrl) -> ContractRequest {
        ContractRequest(self.0.head(url))
    }

    pub(super) fn post(&self, url: impl IntoUrl) -> ContractRequest {
        ContractRequest(self.0.post(url))
    }

    pub(super) fn patch(&self, url: impl IntoUrl) -> ContractRequest {
        ContractRequest(self.0.patch(url))
    }

    pub(super) fn request(&self, method: Method, url: impl IntoUrl) -> ContractRequest {
        ContractRequest(self.0.request(method, url))
    }
}

pub(super) struct ContractRequest(RequestBuilder);

impl ContractRequest {
    pub(super) fn header<K, V>(self, key: K, value: V) -> Self
    where
        HeaderName: TryFrom<K>,
        <HeaderName as TryFrom<K>>::Error: Into<http::Error>,
        HeaderValue: TryFrom<V>,
        <HeaderValue as TryFrom<V>>::Error: Into<http::Error>,
    {
        Self(self.0.header(key, value))
    }

    pub(super) fn bearer_auth(self, token: impl std::fmt::Display) -> Self {
        Self(self.0.bearer_auth(token))
    }

    pub(super) fn body(self, body: impl Into<reqwest::Body>) -> Self {
        Self(self.0.body(body))
    }

    pub(super) fn json(self, json: &(impl serde::Serialize + ?Sized)) -> Self {
        Self(self.0.json(json))
    }

    pub(super) fn timeout(self, timeout: std::time::Duration) -> Self {
        Self(self.0.timeout(timeout))
    }

    pub(super) async fn send(self) -> reqwest::Result<Response> {
        let (client, request) = self.0.build_split();
        let request = request?;
        let (method, url) = (request.method().clone(), request.url().clone());
        let response = client.execute(request).await?;
        Ok(check(&method, &url, response).await)
    }
}

async fn check(method: &Method, url: &Url, response: Response) -> Response {
    let path = url.path();
    // CORS preflight is transport negotiation, not a contract operation.
    if (path != "/api" && !path.starts_with("/api/")) || method == Method::OPTIONS {
        return response;
    }
    let status = response.status().as_u16();
    let media_type = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.split(';').next().unwrap().trim().to_ascii_lowercase());
    // HEAD answers as GET does, without the body.
    let lookup = if method == Method::HEAD {
        "get".to_owned()
    } else {
        method.as_str().to_ascii_lowercase()
    };
    let template = template_for(path);
    let label = format!("{method} {} {status}", template.unwrap_or(path));
    if KNOWN_DRIFT
        .iter()
        .any(|&(m, t, s, _)| m == method.as_str() && t == template.unwrap_or(path) && s == status)
    {
        return response;
    }
    let operation = template
        .map(|template| format!("/paths/{}/{lookup}", escape(template)))
        .filter(|pointer| DOCUMENT.pointer(pointer).is_some());
    let Some(operation) = operation else {
        // Outside the contract only the shared error envelope is acceptable.
        assert!(
            status >= 400 && media_type.as_deref() == Some("application/json"),
            "contract: {label}: operation is not in the contract"
        );
        if method == Method::HEAD {
            return response;
        }
        return validate(&label, "/components/schemas/ErrorResponse", response).await;
    };
    let responses = DOCUMENT.pointer(&format!("{operation}/responses")).unwrap();
    let key = [
        status.to_string(),
        format!("{}XX", status / 100),
        "default".into(),
    ]
    .into_iter()
    .find(|key| responses.get(key).is_some())
    .unwrap_or_else(|| panic!("contract: {label}: status is not documented"));
    let pointer = resolve(format!("{operation}/responses/{key}"));
    let declared = DOCUMENT.pointer(&pointer).unwrap();
    for (name, header) in declared["headers"].as_object().into_iter().flatten() {
        let header = match header["$ref"].as_str() {
            Some(target) => DOCUMENT.pointer(&resolve(target[1..].to_owned())).unwrap(),
            None => header,
        };
        assert!(
            header["required"] != Value::Bool(true) || response.headers().contains_key(name),
            "contract: {label}: required header {name} is missing"
        );
    }
    let content = declared["content"].as_object();
    let Some(media_type) = media_type else {
        assert!(
            content.is_none_or(|content| content.is_empty()) || method == Method::HEAD,
            "contract: {label}: response has no body but the contract declares one"
        );
        return response;
    };
    assert!(
        content.is_some_and(|content| content.contains_key(&media_type)),
        "contract: {label}: media type {media_type} is not documented"
    );
    if media_type != "application/json" || method == Method::HEAD {
        return response;
    }
    let schema = format!("{pointer}/content/{}/schema", escape(&media_type));
    validate(&label, &schema, response).await
}

/// Picks the template whose literal segments match the most of `path`, so
/// `/config/sources` beats `/config/{id}`.
fn template_for(path: &str) -> Option<&'static str> {
    let segments: Vec<_> = path.split('/').collect();
    DOCUMENT["paths"]
        .as_object()
        .unwrap()
        .keys()
        .filter_map(|template| {
            let parts: Vec<_> = template.split('/').collect();
            (parts.len() == segments.len()).then_some(())?;
            let mut literal = 0;
            for (part, segment) in parts.iter().zip(&segments) {
                if part.starts_with('{') && part.ends_with('}') {
                    (!segment.is_empty()).then_some(())?;
                } else if part == segment {
                    literal += 1;
                } else {
                    return None;
                }
            }
            Some((literal, template.as_str()))
        })
        .max_by_key(|(literal, _)| *literal)
        .map(|(_, template)| template)
}

/// Follows `$ref` chains from the object at `pointer` to the pointer of its target.
fn resolve(mut pointer: String) -> String {
    while let Some(target) = DOCUMENT.pointer(&pointer).unwrap()["$ref"].as_str() {
        pointer = target.strip_prefix('#').unwrap().to_owned();
    }
    pointer
}

fn escape(segment: &str) -> String {
    segment.replace('~', "~0").replace('/', "~1")
}

async fn validate(label: &str, pointer: &str, response: Response) -> Response {
    let status = response.status();
    let version = response.version();
    let headers = response.headers().clone();
    let bytes = response.bytes().await.unwrap();
    let body: Value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|error| panic!("contract: {label}: body is not JSON: {error}"));
    let validator = VALIDATORS
        .lock()
        .unwrap()
        .entry(pointer.to_owned())
        .or_insert_with(|| {
            // JSON pointers in a URI fragment are percent-encoded.
            let fragment = pointer.replace('{', "%7B").replace('}', "%7D");
            let schema = serde_json::json!({ "$ref": format!("{CONTRACT_URL}#{fragment}") });
            let validator = jsonschema::options()
                .with_draft(Draft::Draft202012)
                .with_registry(&REGISTRY)
                .build(&schema)
                .unwrap_or_else(|error| panic!("contract: {label}: {error}"));
            Arc::new(validator)
        })
        .clone();
    let errors: Vec<_> = validator
        .iter_errors(&body)
        .map(|error| format!("{} at {}", error, error.instance_path()))
        .collect();
    assert!(
        errors.is_empty(),
        "contract: {label}: {}\nbody: {body}",
        errors.join("; ")
    );
    let mut rebuilt = http::Response::builder().status(status).version(version);
    *rebuilt.headers_mut().unwrap() = headers;
    Response::from(rebuilt.body(bytes).unwrap())
}

/// Reads the suite's scenario tests never reach still have to match the contract.
#[tokio::test]
async fn every_parameterless_read_matches_the_contract() {
    let app = super::TestApp::new(|_| {}).await;
    for (template, item) in DOCUMENT["paths"].as_object().unwrap() {
        if item.get("get").is_some() && !template.contains('{') {
            app.get(template).send().await.unwrap();
        }
    }
    app.shutdown().await;
}
