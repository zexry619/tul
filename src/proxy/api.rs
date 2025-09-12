use worker::*;
use std::collections::HashSet;
use reqwest::{Client, Method, header::HeaderMap};
use tokio::{sync::OnceCell};
use http::Uri;


static HOP_HEADERS: OnceCell<HashSet<String>> = OnceCell::const_new();


async fn get_hop_headers() -> HashSet<String> {
    let mut headers = HashSet::new();
    
    // RFC 2616 定义的逐跳头
    headers.insert("connection".to_string());
    headers.insert("keep-alive".to_string());
    headers.insert("proxy-authenticate".to_string());
    headers.insert("proxy-authorization".to_string());
    headers.insert("te".to_string());
    headers.insert("trailer".to_string());
    headers.insert("transfer-encoding".to_string());
    headers.insert("upgrade".to_string());
    
    // 应该由代理重新生成的头
    headers.insert("x-forwarded-for".to_string());
    headers.insert("x-forwarded-host".to_string());
    headers.insert("x-forwarded-proto".to_string());
    headers.insert("x-real-ip".to_string());
    
    // Cloudflare 特定的头
    headers.insert("cf-connecting-ip".to_string());
    headers.insert("cf-ray".to_string());
    headers.insert("cf-ipcountry".to_string());
    headers.insert("cf-request-id".to_string());
    
    // 其他代理相关的头
    headers.insert("via".to_string());
    headers.insert("x-forwarded-port".to_string());
    headers.insert("x-forwarded-server".to_string());

    headers
}


pub async fn handler(mut req: Request, uri: Uri) -> Result<Response> {
    let client = Client::new();

    let method = match req.method() {
        worker::Method::Get => reqwest::Method::GET,
        worker::Method::Post => reqwest::Method::POST,
        worker::Method::Put => reqwest::Method::PUT,
        worker::Method::Delete => reqwest::Method::DELETE,
        worker::Method::Head => reqwest::Method::HEAD,
        worker::Method::Options => reqwest::Method::OPTIONS,
        worker::Method::Patch => reqwest::Method::PATCH,
        _ => return Response::error("Not supported method", 404),
    };
    let hops = HOP_HEADERS.get_or_init(|| async {
        get_hop_headers().await
    }).await;

    let mut request_builder = client.request(method, uri.to_string());
    for (key, value) in req.headers().entries() {
        if hops.contains(key.as_str()) {
            continue;
        }
        request_builder = request_builder.header(&key, value);
    }
    request_builder = request_builder.header("Host", uri.host().unwrap());
    
    if let Ok(body) = req.bytes().await {
        if !body.is_empty() {
            request_builder = request_builder.body(body);
        }
    }
    match request_builder.send().await {
        Ok(response) => {
            let status = response.status().as_u16();
            let headers = Headers::new();
            
            for (key, value) in response.headers().iter() {
                if let Ok(value) = value.to_str() {
                    if hops.contains(key.as_str()) {
                        continue;
                    }
                    if key == "content-encoding" {
                        continue;
                    }
                    headers.append(key.as_str(), value);
                }
            }
            
            let body = response.bytes().await.map_err(|e| {
                console_error!("Failed to read response body: {:?}", e);
                Error::RustError(format!("Failed to read response body: {:?}", e))
            })?;
            return Ok(Response::builder()
                .with_status(status)
                .with_headers(headers)
                .body(ResponseBody::Body(body.to_vec())));
        }
        Err(e) => {
            return Response::error(e.to_string(), 500);
        }
    };
} 