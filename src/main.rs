



pub struct User {
    pub uuid: String,
    pub email: String,
    pub password: String,
    pub role: String
}

pub struct LoginRequestDTO {
    pub email: String,
    pub password: String
}

pub struct LoginResponseDTO {
    pub token: String
} 