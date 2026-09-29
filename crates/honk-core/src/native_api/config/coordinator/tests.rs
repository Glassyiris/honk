use super::*;

#[test]
fn a_written_but_unconfirmed_replacement_is_not_retryable() {
    let response = write_error(WriteError::ChangedButNotDurable).into_response();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(response.headers().get("retry-after").is_none());
}
