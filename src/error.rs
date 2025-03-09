use thiserror::Error;
use tokio::sync::broadcast::error;
use serde::{Serialize, Deserialize};
use std::convert::Infallible;
use warp::{http::StatusCode, reply::with_status, Rejection, Reply};



#[derive(Error, Debug)]
pub enum Error{
    #[error("wrong credentials")]
    WrongCredentialsError,

    #[error("JWT creation error")]
    JWTTokenCreationError,
    
    #[error("JWT error")]
    JWTTokenError,
    
    #[error("No auth header errror")]
    NoAuthHeaderError,
    
    #[error("No permission error")]
    NoPermissionError,
    
    #[error("Invalid auth header error")]
    InvalidAuthHeaderError
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct ErrorResponse{
    message: String,
    status: String
}

impl warp::reject::Reject for Error {}

pub async fn handle_rejection(err: Rejection) -> std::result::Result<impl Reply, Infallible> {
    let (code, message) = if err.is_not_found() {
        (StatusCode::NOT_FOUND, "Not Found".to_string())
    } else if let Some(e) = err.find::<Error>(){
        match e {
            Error::WrongCredentialsError  => (StatusCode::FORBIDDEN, e.to_string()),
            Error::NoPermissionError => (StatusCode::UNAUTHORIZED, e.to_string()),
            Error::JWTTokenError => (StatusCode::UNAUTHORIZED, e.to_string()),
            Error::JWTTokenCreationError => (
                StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error".to_string(),
            ),
            _ => (StatusCode::BAD_REQUEST, e.to_string()),
        }
    }else if err.find::<warp::reject::MethodNotAllowed>().is_some(){
        (
            StatusCode::METHOD_NOT_ALLOWED,
            "Method Not Allowed".to_string(),
        )
    }else{
        eprintln!("unhandled error: {:?}", err);
        (
            StatusCode::INTERNAL_SERVER_ERROR, 
            "Internal Server Error".to_string()
        )
    };

    let json = warp::reply::json(&ErrorResponse{
        status: code.to_string(),
        message,
    });
    Ok(warp::reply::with_status(json, code))
}