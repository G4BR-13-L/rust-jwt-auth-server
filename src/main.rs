
use auth::{with_auth, Role};
use error::Error::*;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, hash::Hash};
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
    pub role: String
}

#[derive(Deserialize, Serialize)]
pub struct LoginRequestDTO {
    pub email: String,
    pub password: String
}


#[derive(Deserialize, Serialize)]
pub struct LoginResponseDTO {
    pub token: String
} 

#[tokio::main(flavor = "multi_thread")]
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
    
    warp::serve(routes).run(([127,0,0,1], 8000)).await;

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

            Ok(reply::json(&LoginResponseDTO {token}))
        }
        None => Err(reject::custom(WrongCredentialsError)),
        
    }

}

pub async fn user_handler(uuid: String) -> WebResult<impl Reply> {
    Ok(format!("Hello user {}", uuid))
}

pub async fn admin_handler(uuid: String) -> WebResult<impl Reply> {
    Ok(format!("Hello admi {}", uuid))
}

fn init_users() -> HashMap<String, User> {
    let mut map = HashMap::new();
    map.insert(
        String::from("1"),
        User {
            uuid: String::from("1"),
            email: String::from("user@userland.com"),
            password: String::from("12345678"),
            role: String::from("User")
        },
    );

    map.insert(
        String::from("2"),
        User {
            uuid: String::from("2"),
            email: String::from("admin@adminland.com"),
            password: String::from("12345678"),
            role: String::from("Admin")
        },
    );

    map

}