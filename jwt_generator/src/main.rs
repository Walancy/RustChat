use dotenv::dotenv;
use jsonwebtoken::{encode, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use std::env;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Serialize, Deserialize)]

struct Claims {
    sub: String,
    exp: usize,
}

fn generate_jwt(username: &str, secret: &[u8]) -> String {
    let expiration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs()
        + 60 * 60; // 1 hour

    let claims = Claims {
        sub: username.to_owned(),
        exp: expiration as usize,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret),
    )
    .expect("Failed to generate JWT")
}

fn main() {
    dotenv().ok();

    let secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    let secret_bytes = secret.as_bytes();

    let usernames = vec!["admin 1", "admin 2"];

    for username in usernames {
        let token = generate_jwt(username, secret_bytes);
        println!("\nUsername: {}, Token: {}\n", username, token);
    }
}
