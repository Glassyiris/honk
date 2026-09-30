use super::*;

#[test]
fn a_written_but_unconfirmed_replacement_is_not_retryable() {
    let response = write_error(WriteError::ChangedButNotDurable).into_response();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(response.headers().get("retry-after").is_none());
}

#[test]
fn store_refusals_keep_the_write_stage_and_name_the_reason() {
    for (error, reason) in [
        (WriteError::UnsafePath, "unsafe_path"),
        (WriteError::SecretSource, "listener_secret_source"),
        (WriteError::SecretContent, "listener_secret_in_content"),
    ] {
        let error = write_error(error);
        assert_eq!(error.status, StatusCode::FORBIDDEN);
        assert_eq!(
            error.into_details(),
            Some(json!({"stage":"write","reason":reason}))
        );
    }
}
