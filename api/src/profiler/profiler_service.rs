use std::net::SocketAddr;

use bytes::Bytes;
use http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use http::{Method, Request, Response, StatusCode};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

pub struct ProfilerEndpointConfig {
    pub address: SocketAddr,
}

/// Checks whether jemalloc profiling is activated an returns an error response if not.
fn require_profiling_activated(
    prof_ctl: &jemalloc_pprof::JemallocProfCtl,
) -> Result<(), (StatusCode, String)> {
    if prof_ctl.activated() {
        Ok(())
    } else {
        Err((StatusCode::FORBIDDEN, "heap profiling not activated".into()))
    }
}

async fn get_pprof_dump(flamegraph: bool) -> Response<Full<Bytes>> {
    let mut prof_ctl = jemalloc_pprof::PROF_CTL
        .as_ref()
        .expect("no profctl?")
        .lock()
        .await;
    match require_profiling_activated(&prof_ctl) {
        Ok(()) => {
            if flamegraph {
                match prof_ctl.dump_flamegraph() {
                    Ok(svg) => Response::builder()
                        .status(200)
                        .header(CONTENT_LENGTH, svg.len())
                        .header(CONTENT_TYPE, "image/svg+xml")
                        .body(svg.into())
                        .unwrap(),
                    Err(error) => Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body(error.to_string().into())
                        .unwrap(),
                }
            } else {
                match prof_ctl.dump_pprof() {
                    Ok(pprof) => Response::builder()
                        .status(200)
                        .header(CONTENT_LENGTH, pprof.len())
                        .body(pprof.into())
                        .unwrap(),
                    Err(error) => Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body(error.to_string().into())
                        .unwrap(),
                }
            }
        }
        Err((status, error_str)) => Response::builder()
            .status(status)
            .body(error_str.into())
            .unwrap(),
    }
}

async fn handle_profiler_request(
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let response: Response<Full<Bytes>> = match (req.method(), req.uri().path()) {
        (&Method::GET, "/pprof") => get_pprof_dump(false).await,
        (&Method::GET, "/pprof/flamegraph") => get_pprof_dump(true).await,
        (&Method::GET, "/") => Response::builder()
            .status(200)
            .body("profiler tools are exposed via /pprof. There is nothing else to see here".into())
            .unwrap(),
        _ => Response::builder()
            .status(404)
            .body("Invalid URL".into())
            .unwrap(),
    };

    Ok(response)
}

pub async fn run_profiler_endpoint(
    config: &ProfilerEndpointConfig,
    mut stop_rx: oneshot::Receiver<()>,
) -> eyre::Result<()> {
    tracing::info!(
        address = config.address.to_string(),
        "Starting profiler listener"
    );

    let listener = TcpListener::bind(&config.address).await?;
    loop {
        tokio::select! {
            result = listener.accept() => {
                let (stream, _) = result?;
                tokio::spawn(http1::Builder::new().serve_connection(
                    TokioIo::new(stream),
                    service_fn(move |req| {
                        handle_profiler_request(req)
                    }),
                ));
            },
            _ = &mut stop_rx => {
                break
            }
        }
    }
    Ok(())
}
