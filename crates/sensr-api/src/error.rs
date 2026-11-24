//! HTTP error responses.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use sensr_ipc::{ClientError, ErrorKind, IpcError};
use serde_json::json;

/// An error as the API returns it: `{status, message, validations}`.
#[derive(Debug)]
pub struct ApiError {
    /// HTTP status.
    pub status: StatusCode,
    /// Message.
    pub message: String,
    /// Field messages (OPNsense `validations` map: path → message).
    pub validations: Vec<sensr_ipc::ValidationIssue>,
}

impl ApiError {
    /// An error without field details.
    pub fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
            validations: Vec::new(),
        }
    }
}

fn status_of(kind: ErrorKind) -> StatusCode {
    match kind {
        ErrorKind::BadRequest => StatusCode::BAD_REQUEST,
        ErrorKind::VersionMismatch => StatusCode::BAD_GATEWAY,
        ErrorKind::Unauthenticated => StatusCode::UNAUTHORIZED,
        ErrorKind::Forbidden => StatusCode::FORBIDDEN,
        ErrorKind::NotFound => StatusCode::NOT_FOUND,
        ErrorKind::Validation => StatusCode::UNPROCESSABLE_ENTITY,
        ErrorKind::Conflict => StatusCode::CONFLICT,
        ErrorKind::TooManyRequests => StatusCode::TOO_MANY_REQUESTS,
        ErrorKind::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        ErrorKind::ApplyFailed | ErrorKind::Internal => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

impl From<IpcError> for ApiError {
    fn from(e: IpcError) -> Self {
        Self {
            status: status_of(e.kind),
            message: e.message,
            validations: e.validations,
        }
    }
}

impl From<ClientError> for ApiError {
    fn from(e: ClientError) -> Self {
        match e {
            ClientError::Agent(e) => e.into(),
            ClientError::Connect { .. } | ClientError::Closed => {
                tracing::error!(error = %e, "sensr-agent unreachable");
                Self::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "sensr-agent is not reachable",
                )
            }
            other => {
                tracing::error!(error = %other, "ipc failure");
                Self::new(
                    StatusCode::BAD_GATEWAY,
                    "ipc failure talking to sensr-agent",
                )
            }
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let validations: serde_json::Map<String, serde_json::Value> = self
            .validations
            .into_iter()
            .map(|v| (v.path, json!(v.message)))
            .collect();
        let mut body = json!({"status": "failed", "message": self.message});
        if !validations.is_empty() {
            body["validations"] = validations.into();
        }
        (self.status, Json(body)).into_response()
    }
}
