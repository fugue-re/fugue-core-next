use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use fugue_core::engine::EngineError;
use fugue_core::loader::LoaderError;
use fugue_core::project::ProjectError;
use fugue_core::queries::QueryError;
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum WorkbenchError {
    #[error("{0}")]
    BadRequest(String),
    #[error("analysis engine failure: {0}")]
    Engine(#[from] EngineError),
    #[error("failed to load input: {0}")]
    Loader(#[from] LoaderError),
    #[error("no function at {0}")]
    NoFunction(String),
    #[error("no project open")]
    NoProject,
    #[error("address {0} is not mapped")]
    NotMapped(String),
    #[error("project failure: {0}")]
    Project(#[from] ProjectError),
    #[error("query failure: {0}")]
    Query(#[from] QueryError),
    #[error("background analysis task cancelled")]
    TaskCancelled,
    #[error("no renderer available for il form {0}")]
    UnrenderableForm(String),
}

impl WorkbenchError {
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::BadRequest(message.into())
    }

    pub fn no_function(address: impl Into<String>) -> Self {
        Self::NoFunction(address.into())
    }

    pub fn not_mapped(address: impl Into<String>) -> Self {
        Self::NotMapped(address.into())
    }

    pub fn unrenderable_form(form: impl Into<String>) -> Self {
        Self::UnrenderableForm(form.into())
    }

    fn status(&self) -> StatusCode {
        match self {
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::NoProject => StatusCode::CONFLICT,
            Self::NoFunction(_) | Self::NotMapped(_) => StatusCode::NOT_FOUND,
            Self::UnrenderableForm(_) => StatusCode::NOT_IMPLEMENTED,
            Self::Engine(_)
            | Self::Loader(_)
            | Self::Project(_)
            | Self::Query(_)
            | Self::TaskCancelled => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl IntoResponse for WorkbenchError {
    fn into_response(self) -> Response {
        let status = self.status();
        (status, Json(json!({ "error": self.to_string() }))).into_response()
    }
}
