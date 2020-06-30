use std::convert::Infallible;

use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server};
use hyper::server::conn::AddrStream;

static DEFAULT_ADDR: &str = "127.0.0.1:5000";

async fn hello(_: Request<Body>) -> Result<Response<Body>, Infallible> {
    Ok(Response::new(Body::from("<h1>Hello World!</h1>")))
}

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // For every connection, we must make a `Service` to handle all
    // incoming HTTP requests on said connection.
    let make_svc = make_service_fn(|socket: &AddrStream| {
        // This is the `Service` that will handle the connection.
        // `service_fn` is a helper to convert a function that
        // returns a Response into a `Service`.
        let remote_addr = socket.remote_addr();
        async move {
            Ok::<_, Infallible>(service_fn(move|req: Request<Body>|{
                println!("handle conn from {:?}", remote_addr);
                hello(req)
            }))
        }
    });

    let addr = DEFAULT_ADDR.parse().expect("parse addr failed");

    let server = Server::bind(&addr).serve(make_svc);

    println!("Listening on http://{}", addr);

    server.await?;

    Ok(())
}
