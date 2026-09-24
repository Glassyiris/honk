use super::*;

const USER: &str = "operator";
const PASSWORD: &str = "a-long-enough-password";

struct PasswordApp {
    app: TestApp,
    data: tempfile::TempDir,
}

impl std::ops::Deref for PasswordApp {
    type Target = TestApp;
    fn deref(&self) -> &TestApp {
        &self.app
    }
}

/// A password-mode listener with its own data directory, so these tests run independently.
async fn password_app() -> PasswordApp {
    let data = tempfile::tempdir().expect("temp data directory");
    let path = data.path().to_string_lossy().into_owned();
    let app = TestApp::new(|config| {
        config.global.data_dir = path;
        config.experimental.native_api.secret = String::new();
        config.experimental.native_api.password_auth = true;
    })
    .await;
    PasswordApp { app, data }
}

impl PasswordApp {
    /// Rows in the state db's `admin` table.
    fn administrators(&self) -> i64 {
        rusqlite::Connection::open(self.data.path().join("state/honk.db"))
            .unwrap()
            .query_row("SELECT count(*) FROM admin", [], |row| row.get(0))
            .unwrap()
    }

    async fn shutdown(self) {
        self.app.shutdown().await;
    }
}

async fn post_credentials(app: &TestApp, path: &str, user: &str, password: &str) -> Response {
    app.client
        .post(app.url(path))
        .json(&serde_json::json!({"username": user, "password": password}))
        .send()
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn discovery_reports_the_mode_and_setup_state() {
    let app = password_app().await;
    // Discovery answers without a credential; version and capabilities still do not.
    let body: Value = app
        .client
        .get(app.url("/api"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["auth"]["mode"], "password");
    assert_eq!(body["auth"]["setup_required"], true);
    assert_eq!(body["auth"]["anonymous_loopback"], false);
    assert_eq!(body["links"]["auth_setup"], "/api/v1/auth/setup");
    assert_eq!(body["links"]["auth_login"], "/api/v1/auth/login");
    let alias: Value = app
        .client
        .get(app.url("/api/v1/discovery"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(alias, body, "the alias answers exactly as /api does");
    error_response(
        app.client
            .get(app.url("/api/v1/version"))
            .send()
            .await
            .unwrap(),
        StatusCode::UNAUTHORIZED,
        "authentication_required",
    )
    .await;
    app.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn setup_claims_the_one_account() {
    let app = password_app().await;
    // Before an administrator exists, login says so and protected resources stay closed.
    let refused = post_credentials(&app, "/api/v1/auth/login", USER, PASSWORD).await;
    error_response(refused, StatusCode::CONFLICT, "setup_required").await;
    let created = post_credentials(&app, "/api/v1/auth/setup", USER, PASSWORD).await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let session: Value = created.json().await.unwrap();
    let token = session["token"].as_str().unwrap().to_owned();
    assert!(token.starts_with("hnk1_"));
    assert!(session["expires_at"].as_str().unwrap().ends_with('Z'));
    // The session is a bearer for every protected resource; anything else is not.
    assert_eq!(
        app.client
            .get(app.url("/api/v1/version"))
            .bearer_auth(&token)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    error_response(
        app.client
            .get(app.url("/api/v1/version"))
            .bearer_auth("hnk1_not-a-session")
            .send()
            .await
            .unwrap(),
        StatusCode::UNAUTHORIZED,
        "authentication_required",
    )
    .await;
    // A second setup is refused whoever asks, and discovery stops asking for one.
    error_response(
        post_credentials(&app, "/api/v1/auth/setup", "other", PASSWORD).await,
        StatusCode::CONFLICT,
        "setup_already_completed",
    )
    .await;
    let discovery: Value = app
        .client
        .get(app.url("/api"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(discovery["auth"]["setup_required"], false);
    app.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn login_issues_a_session_and_logout_ends_only_that_one() {
    let app = password_app().await;
    let first: Value = post_credentials(&app, "/api/v1/auth/setup", USER, PASSWORD)
        .await
        .json()
        .await
        .unwrap();
    let token = first["token"].as_str().unwrap().to_owned();
    // A wrong password and a wrong username fail the same way.
    for (user, password) in [(USER, "a-different-password"), ("nobody", PASSWORD)] {
        error_response(
            post_credentials(&app, "/api/v1/auth/login", user, password).await,
            StatusCode::UNAUTHORIZED,
            "invalid_credentials",
        )
        .await;
    }
    let logged_in = post_credentials(&app, "/api/v1/auth/login", USER, PASSWORD).await;
    assert_eq!(logged_in.status(), StatusCode::OK);
    let second: Value = logged_in.json().await.unwrap();
    let second_token = second["token"].as_str().unwrap().to_owned();
    assert_ne!(second_token, token, "each login issues its own session");
    // Logout ends that session and leaves the other one alone.
    let out = app
        .client
        .post(app.url("/api/v1/auth/logout"))
        .bearer_auth(&second_token)
        .send()
        .await
        .unwrap();
    assert_eq!(out.status(), StatusCode::NO_CONTENT);
    error_response(
        app.client
            .get(app.url("/api/v1/version"))
            .bearer_auth(&second_token)
            .send()
            .await
            .unwrap(),
        StatusCode::UNAUTHORIZED,
        "authentication_required",
    )
    .await;
    assert_eq!(
        app.client
            .get(app.url("/api/v1/version"))
            .bearer_auth(&token)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    app.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn credentials_are_rejected_before_they_reach_the_store() {
    let app = password_app().await;
    // Wrong media type, unknown fields, a short password and a query parameter are all refused.
    let text = app
        .client
        .post(app.url("/api/v1/auth/setup"))
        .header("content-type", "text/plain")
        .body("{}")
        .send()
        .await
        .unwrap();
    error_response(
        text,
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "unsupported_media_type",
    )
    .await;
    let unknown = app
        .client
        .post(app.url("/api/v1/auth/setup"))
        .json(&serde_json::json!({"username": USER, "password": PASSWORD, "role": "admin"}))
        .send()
        .await
        .unwrap();
    error_response(unknown, StatusCode::BAD_REQUEST, "invalid_request").await;
    error_response(
        post_credentials(&app, "/api/v1/auth/setup", USER, "short").await,
        StatusCode::BAD_REQUEST,
        "invalid_request",
    )
    .await;
    error_response(
        post_credentials(&app, "/api/v1/auth/setup", "not a name", PASSWORD).await,
        StatusCode::BAD_REQUEST,
        "invalid_request",
    )
    .await;
    // A token in the query is a credential, and query credentials are never accepted.
    let queried = app
        .client
        .post(app.url("/api/v1/auth/setup?token=x"))
        .json(&serde_json::json!({"username": USER, "password": PASSWORD}))
        .send()
        .await
        .unwrap();
    error_response(queried, StatusCode::UNAUTHORIZED, "authentication_required").await;
    assert_eq!(
        app.administrators(),
        0,
        "no account was created by a refused request"
    );
    app.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn token_mode_has_no_password_endpoints() {
    let app = TestApp::new(|_| {}).await;
    let body: Value = app.get("/api").send().await.unwrap().json().await.unwrap();
    assert_eq!(body["auth"]["mode"], "token");
    assert_eq!(body["auth"]["setup_required"], false);
    assert_eq!(body["links"]["auth_setup"], Value::Null);
    for path in ["/api/v1/auth/setup", "/api/v1/auth/login"] {
        let response = app
            .client
            .post(app.url(path))
            .json(&serde_json::json!({"username": USER, "password": PASSWORD}))
            .send()
            .await
            .unwrap();
        error_response(response, StatusCode::NOT_FOUND, "capability_not_supported").await;
    }
    app.shutdown().await;
}

#[tokio::test]
async fn credential_media_types_are_case_insensitive_but_not_duplicated() {
    for path in ["/api/v1/auth/setup", "/api/v1/auth/login"] {
        let app = password_app().await;
        let expected = if path.ends_with("/login") {
            assert_eq!(
                post_credentials(&app, "/api/v1/auth/setup", USER, PASSWORD)
                    .await
                    .status(),
                StatusCode::CREATED,
            );
            StatusCode::OK
        } else {
            StatusCode::CREATED
        };
        let body = json!({"username": USER, "password": PASSWORD}).to_string();
        let duplicate = app
            .client
            .post(app.url(path))
            .header("content-type", "application/json")
            .header("content-type", "text/plain")
            .body(body.clone())
            .send()
            .await
            .unwrap();
        error_response(duplicate, StatusCode::BAD_REQUEST, "invalid_request").await;
        let mixed_case = app
            .client
            .post(app.url(path))
            .header("content-type", "Application/JSON; charset=utf-8")
            .body(body)
            .send()
            .await
            .unwrap();
        assert_eq!(mixed_case.status(), expected);
        app.shutdown().await;
    }
}
