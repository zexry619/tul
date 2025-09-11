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
    
    Router::new()
        .on_async("/:path", handler)
        .run(req, env)
        .await 
}