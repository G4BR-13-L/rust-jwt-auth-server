use auth::{with_auth, Role};
use error::Error::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;
use warp::{reject, reply, Filter, Rejection, Reply};

mod auth;
mod error;

type Result<T> = std::result::Result<T, error::Error>;
type WebResult<T> = std::result::Result<T, Rejection>;
type Users = Arc<HashMap<String, User>>;

#[derive(Clone)]
pub struct User {
    pub uuid: String,
    pub email: String,
    pub password: String,
    pub role: String,
}

#[derive(Serialize, Deserialize)]
pub struct LoginRequestDTO {
    pub email: String,
    pub password: String,
}

#[derive(Serialize, Deserialize)]
pub struct LoginResponseDTO {
    pub token: String,
}

#[tokio::main]
async fn main() {
    let users = Arc::new(init_users());

    let login_route = warp::path!("login")
        .and(warp::post())
        .and(with_users(users.clone()))
        .and(warp::body::json())
        .and_then(login_handler);

    let user_route = warp::path!("user")
        .and(with_auth(Role::User))
        .and_then(user_handler);
    let admin_route = warp::path!("admin")
        .and(with_auth(Role::Admin))
        .and_then(admin_handler);

    let routes = login_route
        .or(user_route)
        .or(admin_route)
        .recover(error::handle_rejection);

    warp::serve(routes).run(([127, 0, 0, 1], 8000)).await;
}

fn with_users(users: Users) -> impl Filter<Extract = (Users,), Error = Infallible> + Clone {
    warp::any().map(move || users.clone())
}

pub async fn login_handler(users: Users, body: LoginRequestDTO) -> WebResult<impl Reply> {
    match users
        .iter()
        .find(|(_uuid, user)| user.email == body.email && user.password == body.password)
    {
        Some((uuid, user)) => {
            let token = auth::create_jwt(&uuid, &Role::from_str(&user.role))
                .map_err(|e| reject::custom(e))?;
            Ok(reply::json(&LoginResponseDTO { token }))
        }
        None => Err(reject::custom(WrongCredentialsError)),
    }
}

pub async fn user_handler(uuid: String) -> WebResult<impl Reply> {
    Ok(format!("Hello User {}", uuid))
}

pub async fn admin_handler(uuid: String) -> WebResult<impl Reply> {
    Ok(format!("Hello Admin {}", uuid))
}

fn init_users() -> HashMap<String, User> {
    let mut map = HashMap::new();
    map.insert(
        String::from("1"),
        User {
            uuid: String::from("1"),
            email: String::from("user@userland.com"),
            password: String::from("12345678"),
            role: String::from("User"),
        },
    );
    map.insert(
        String::from("2"),
        User {
            uuid: String::from("2"),
            email: String::from("admin@adminland.com"),
            password: String::from("12345678"),
            role: String::from("Admin"),
        },
    );
    map
}

#[cfg(test)]
mod tests {
    use super::*;
    use warp::{http::StatusCode,test};
    use std::collections::HashMap;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_login_handler_success() {
        let users = Arc::new(init_users());
        let body = LoginRequestDTO {
            email: "user@userland.com".to_string(),
            password: "12345678".to_string(),
        };

        let result = login_handler(users, body).await;

        assert!(result.is_ok());
        let response = result.unwrap().into_response();
        let status = response.status();
        assert_eq!(status, 200);

        let body = response.into_body();
        let bytes = warp::hyper::body::to_bytes(body).await.unwrap();
        let response_body: LoginResponseDTO = serde_json::from_slice(&bytes).unwrap();
        assert!(!response_body.token.is_empty());
    }

    #[tokio::test]
    async fn test_login_handler_failure() {
        let users = Arc::new(init_users());
        let body = LoginRequestDTO {
            email: "wrong@user.com".to_string(),
            password: "wrongpassword".to_string(),
        };
    
        let result = login_handler(users, body).await;
    
        // Verifique se o resultado é um erro
        assert!(result.is_err());
    
        // Extraia o erro (Rejection) do Result
        if let Err(rejection) = result {
            // Verifique se o erro é do tipo esperado
            if let Some(error) = rejection.find::<error::Error>() {
                assert_eq!(error.to_string(), "wrong credentials");
            } else {
                panic!("Expected a WrongCredentialsError, but got a different error");
            }
        } else {
            panic!("Expected an error, but got Ok");
        }
    }
}

#[tokio::test]
async fn test_with_auth_success() {
    let user_uuid = "1".to_string();
    let role = Role::User;
    let token = auth::create_jwt(&user_uuid, &role).unwrap();

    // Verifique o token gerado
    println!("Generated token: {}", token);

    let filter = auth::with_auth(role);
    let request = warp::test::request()
        .header("Authorization", format!("Bearer {}", token))
        .filter(&filter);

    let result = request.await;

    // Verifique se o resultado é Ok
    assert!(result.is_ok(), "Expected Ok, but got Err: {:?}", result);

    // Verifique se o UUID retornado é o esperado
    let returned_uuid = result.unwrap();
    assert_eq!(returned_uuid, user_uuid, "Expected UUID {}, but got {}", user_uuid, returned_uuid);
}
#[tokio::test]
async fn test_with_auth_failure() {
    let role = Role::Admin;
    let filter = auth::with_auth(role);
    let request = warp::test::request()
        .header("Authorization", "Bearer invalid_token")
        .filter(&filter);

    let result = request.await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_user_handler() {
    let user_uuid = "1".to_string();
    let result = user_handler(user_uuid.clone()).await;

    assert!(result.is_ok());
    let response = result.unwrap().into_response();
    let status = response.status();
    assert_eq!(status, 200);

    let body = response.into_body();
    let bytes = warp::hyper::body::to_bytes(body).await.unwrap();
    let response_body = String::from_utf8(bytes.to_vec()).unwrap();
    assert_eq!(response_body, format!("Hello User {}", user_uuid));
}

#[tokio::test]
async fn test_admin_handler() {
    let admin_uuid = "2".to_string();
    let result = admin_handler(admin_uuid.clone()).await;

    assert!(result.is_ok());
    let response = result.unwrap().into_response();
    let status = response.status();
    assert_eq!(status, 200);

    let body = response.into_body();
    let bytes = warp::hyper::body::to_bytes(body).await.unwrap();
    let response_body = String::from_utf8(bytes.to_vec()).unwrap();
    assert_eq!(response_body, format!("Hello Admin {}", admin_uuid));
}