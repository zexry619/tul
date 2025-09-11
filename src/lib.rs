use worker::*;

mod proxy;

use crate::proxy::*;


#[event(fetch)]
async fn fetch(
    req: Request,
    env: Env,
    _ctx: Context,
) -> Result<Response> {
    console_error_panic_hook::set_once();
    match Router::new()
        .on_async("/", handler)
        .run(req, env)
        .await {
            Err(_err) => {
                Response::error("hello world", 200)
            }
            Ok(res) => {
                Ok(res)
            }
    }
}