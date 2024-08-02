use base64::engine::general_purpose;
use base64::Engine as _;
use futures_util::{SinkExt, StreamExt};
use jsonwebtoken::{decode, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::protocol::Message;

type Clients = Arc<Mutex<HashMap<usize, tokio::sync::broadcast::Sender<String>>>>;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

#[derive(Debug, Serialize, Deserialize)]
struct MediaMessage {
    r#type: String,
    data: String,
    filename: String,
}

fn validate_token(token: &str, jwt_secret: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(jwt_secret.as_ref()),
        &Validation::default(),
    )
    .map(|data| data.claims)
}

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();
    let jwt_secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");

    let listener = TcpListener::bind("127.0.0.1:8080")
        .await
        .expect("Não conseguiu criar o listener");
    let clients: Clients = Arc::new(Mutex::new(HashMap::new()));
    let (tx, _rx) = broadcast::channel(100);

    println!("Servidor WebSocket escutando em 127.0.0.1:8080");

    while let Ok((stream, _)) = listener.accept().await {
        let clients = clients.clone();
        let tx = tx.clone();
        let mut rx = tx.subscribe();
        let jwt_secret = jwt_secret.clone();

        tokio::spawn(async move {
            let ws_stream = accept_async(stream)
                .await
                .expect("Falha ao aceitar a conexão WebSocket");
            println!("Nova conexão WebSocket");

            let (mut write, mut read) = ws_stream.split();

            // Recebe a primeira mensagem que deve conter o token
            if let Some(Ok(Message::Text(text))) = read.next().await {
                let (username, token) = parse_message(&text);
                match validate_token(&token, &jwt_secret) {
                    Ok(claims) => {
                        println!("Token aceito pelo usuário: {}", claims.sub);
                    }
                    Err(err) => {
                        println!("Token recusado para usuário: {}. Erro: {:?}", username, err);
                        let _ = write
                            .send(Message::Text("Token inválido".to_string()))
                            .await;
                        return;
                    }
                }
            } else {
                println!("Falha na primeira mensagem de conexão");
                return;
            }

            let id = {
                let mut clients = clients.lock().unwrap();
                let id = clients.len() + 1;
                clients.insert(id, tx.clone());
                id
            };

            loop {
                tokio::select! {
                    msg = read.next() => {
                        if let Some(Ok(message)) = msg {
                            match message {
                                Message::Text(text) => {
                                    // Verifica se é uma mensagem de mídia
                                    if let Ok(media_message) = serde_json::from_str::<MediaMessage>(&text) {
                                        if media_message.r#type == "media" {
                                            let decoded_data = general_purpose::STANDARD.decode(&media_message.data).expect("Falha ao decodificar base64");
                                            // Salvar ou processar o arquivo conforme necessário
                                            // Aqui estamos apenas imprimindo o tamanho dos dados recebidos
                                            println!("Recebido arquivo: {} ({} bytes)", media_message.filename, decoded_data.len());
                                            continue;
                                        }
                                    }
                                    tx.send(text.clone()).unwrap();
                                },
                                _ => {},
                            }
                        } else {
                            break;
                        }
                    }
                    msg = rx.recv() => {
                        if let Ok(text) = msg {
                            write.send(Message::Text(text)).await.expect("Falha ao enviar mensagem");
                        }
                    }
                }
            }

            clients.lock().unwrap().remove(&id);
            println!("Conexão WebSocket fechada");
        });
    }
}

fn parse_message(message: &str) -> (String, String) {
    let parts: Vec<&str> = message.splitn(2, ':').collect();
    let username = parts.get(0).unwrap_or(&"").to_string();
    let token = parts.get(1).unwrap_or(&"").to_string();
    (username, token)
}
