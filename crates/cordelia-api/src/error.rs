//! Structured JSON error responses per channels-api.md §2.

use actix_web::{HttpResponse, ResponseError};
use serde::Serialize;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("unauthorized")]
    Unauthorized,

    #[error("not authorized: {0}")]
    Forbidden(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("payload too large")]
    PayloadTooLarge { used_bytes: u64, quota_bytes: u64 },

    #[error("internal error: {0}")]
    Internal(String),
}

#[derive(Serialize)]
struct ErrorBody {
    error: ErrorDetail,
}

#[derive(Serialize)]
struct ErrorDetail {
    code: &'static str,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    used_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    quota_bytes: Option<u64>,
}

impl ResponseError for ApiError {
    fn error_response(&self) -> HttpResponse {
        let (status, code, used, quota) = match self {
            Self::BadRequest(_) => (
                actix_web::http::StatusCode::BAD_REQUEST,
                "bad_request",
                None,
                None,
            ),
            Self::Unauthorized => (
                actix_web::http::StatusCode::UNAUTHORIZED,
                "unauthorized",
                None,
                None,
            ),
            Self::Forbidden(_) => (
                actix_web::http::StatusCode::FORBIDDEN,
                "not_authorized",
                None,
                None,
            ),
            Self::NotFound(_) => (
                actix_web::http::StatusCode::NOT_FOUND,
                "not_found",
                None,
                None,
            ),
            Self::Conflict(_) => (
                actix_web::http::StatusCode::CONFLICT,
                "conflict",
                None,
                None,
            ),
            Self::PayloadTooLarge {
                used_bytes,
                quota_bytes,
            } => (
                actix_web::http::StatusCode::PAYLOAD_TOO_LARGE,
                "payload_too_large",
                Some(*used_bytes),
                Some(*quota_bytes),
            ),
            Self::Internal(_) => (
                actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                None,
                None,
            ),
        };

        HttpResponse::build(status).json(ErrorBody {
            error: ErrorDetail {
                code,
                message: self.to_string(),
                used_bytes: used,
                quota_bytes: quota,
            },
        })
    }
}

impl From<cordelia_core::CordeliaError> for ApiError {
    fn from(e: cordelia_core::CordeliaError) -> Self {
        match e {
            cordelia_core::CordeliaError::InvalidChannelName { reason } => {
                Self::BadRequest(format!("invalid channel name: {reason}"))
            }
            cordelia_core::CordeliaError::ChannelNotFound { channel } => {
                Self::NotFound(format!("channel '{channel}' not found"))
            }
            cordelia_core::CordeliaError::ChannelAlreadyExists { channel } => {
                Self::Conflict(format!("channel '{channel}' already exists"))
            }
            cordelia_core::CordeliaError::NotAuthorised { context } => Self::Forbidden(context),
            cordelia_core::CordeliaError::Validation(msg) => Self::BadRequest(msg),
            cordelia_core::CordeliaError::ItemNotFound { item_id } => {
                Self::NotFound(format!("item '{item_id}' not found"))
            }
            other => Self::Internal(other.to_string()),
        }
    }
}
