

pub mod tj;
pub mod websocket;

use worker::*;
use sha2::{Sha224, Digest};
use tokio::{io::AsyncWriteExt, sync::OnceCell};

static EXPECTED_HASH: OnceCell<Vec<u8>> = OnceCell::const_new();
static BUFSIZE: OnceCell<usize> = OnceCell::const_new();

async fn get_expected_hash(cx: &RouteContext<()>) -> Vec<u8> {
    let pw = cx.env
        .var("PASSWORD")
        .map_or("password".to_string(), |x| x.to_string());
    
    let mut hasher = Sha224::new();
    hasher.update(pw.as_bytes());
    hasher.finalize().to_vec()
}


async fn get_bufsize(cx: &RouteContext<()>) -> usize {
    cx.env.var("BUFSIZE")
    .map_or(8196, |x| x.to_string().parse::<usize>().unwrap_or(8196))
}

pub async fn handler(req: Request, cx: RouteContext<()>) -> Result<Response> {
    match req.path().as_str() {
        "/tj" => {
            let expected_hash = EXPECTED_HASH.get_or_init(|| async {
                get_expected_hash(&cx).await
            }).await;
            let buf_size = *BUFSIZE.get_or_init(|| async {
                get_bufsize(&cx).await
            }).await;

            let WebSocketPair { server, client } = WebSocketPair::new()?;
            server.accept()?;

            wasm_bindgen_futures::spawn_local(async move {
                let events = server.events().expect("Failed to get server events");
                let wsstream = websocket::WsStream::new(
                    &server,
                    events,
                    buf_size);
                    
                match tj::Server::parse(expected_hash,wsstream).await {
                    Ok((req, payload)) => {
                        match Socket::builder().connect( req.hostname(), req.port()) {
                            Ok(mut upstream) => {
                                upstream.write(&payload).await.expect("write payload failed");
                                match tokio::io::copy_bidirectional(req.into_inner().as_mut(),&mut upstream).await {
                                    Ok(_) => {
                                        console_log!("copy bidirectional success");
                                    },
                                    Err(e) => {
                                        console_log!("copy bidirectional failed: {}", e)
                                    }
                                }
                            }
                            Err(e) => {
                                console_log!("connect failed: {}", e)
                            }
                        }                       
                    },
                    Err(e) => console_log!("parse request failed: {}", e)
                };
            });
            Response::from_websocket(client)
        }
        _ => Response::error("hello world", 200),
    }
}
