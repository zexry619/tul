

pub mod tj;
pub mod websocket;


use base64::{engine::general_purpose, Engine as _};
use worker::*;
use sha2::{Sha224, Digest};
use tokio::{io::AsyncWriteExt, sync::OnceCell};

static EXPECTED_HASH: OnceCell<Vec<u8>> = OnceCell::const_new();
static BUFSIZE: OnceCell<usize> = OnceCell::const_new();

async fn get_expected_hash(cx: &RouteContext<()>) -> Vec<u8> {
    let pw = cx.env
        .var("PASSWORD")
        .map_or("password".to_string(), |x| x.to_string());
    Sha224::digest(pw.as_bytes())
        .iter()
        .map(|x| format!("{:02x}", x))
        .collect::<String>()
        .as_bytes()
        .to_vec()

}


async fn get_bufsize(cx: &RouteContext<()>) -> usize {
    cx.env.var("BUFSIZE")
    .map_or(4096, |x| x.to_string().parse::<usize>().unwrap_or(4096))
}

pub async fn handler(req: Request, cx: RouteContext<()>) -> Result<Response> {
    console_log!("Request url: {:?}", req.url().unwrap());
    match req.path().as_str() {
        "/tj" => tj(req, cx).await,
        _ => Response::error( "Not Found",404),
    }   
}

pub async fn tj(req: Request, cx: RouteContext<()>) -> Result<Response> {

    let expected_hash = EXPECTED_HASH.get_or_init(|| async {
        get_expected_hash(&cx).await
    }).await;
    let buf_size = *BUFSIZE.get_or_init(|| async {
        get_bufsize(&cx).await
    }).await;


    let WebSocketPair { server, client } = WebSocketPair::new()?;

    let mut response = Response::from_websocket(client)?;
    let mut early_data = None;

    let ws_proto = req.headers().get("sec-websocket-protocol").unwrap_or(None);
    if let Some(proto) = ws_proto {
        response.headers_mut().set("sec-websocket-protocol", proto.as_str())?;
        
        let decoded_bytes = general_purpose::STANDARD_NO_PAD.decode(proto.as_bytes())
            .map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, format!("Invalid base64 encoding: {e}"))
            })?;
        
        early_data = Some(decoded_bytes);
    }

    server.accept()?;

    let early_data_for_async = early_data;
    
    wasm_bindgen_futures::spawn_local(async move {
        let events = server.events().expect("Failed to get server events");
        let mut wsstream = websocket::WsStream::new(
            &server,
            events,
            buf_size,
            early_data_for_async,
            );
        
        console_log!("WebSocket connection established");

        let result = match tj::Server::parse(expected_hash,&mut wsstream).await {
            Ok(req) => {
                match Socket::builder().connect( req.hostname(), req.port()) {
                    Ok(mut upstream) => {
                        match tokio::io::copy_bidirectional(wsstream.as_mut(),&mut upstream).await {
                            Ok(_) => {console_log!("bidirectional success"); Ok(())},
                            Err(e) => {
                                console_log!("copy failed: {}", e);
                                Err(e)
                            }
                        }
                    }
                    Err(e) => {
                        console_log!("connect failed: {}", e);
                        Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "connect failed:"),
                        )
                    }
                }                       
            },
            Err(e) => {
                console_log!("parse request failed: {}", e);
                Err(e)
            }
        };
        if let Err(_e) = result{
             server.close(Some(1000u16), Some("Normal closure")).ok();
        }
       
    });
    Ok(response)
}
