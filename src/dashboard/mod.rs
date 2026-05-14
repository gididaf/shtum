//! Local web dashboard for managing stored secrets and viewing hook-install
//! snippets. Binds 127.0.0.1 only; gated by a random session token. Runs
//! until the process is interrupted (Ctrl+C exits the loop).
//!
//! P-D1 milestone: scaffolding + auth. Serves a single placeholder page;
//! store integration arrives in P-D2.

mod auth;

use std::io::Cursor;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener};

use anyhow::{Context, Result, anyhow};
use tiny_http::{Header, Method, Response, ResponseBox, Server, StatusCode};

use auth::{AuthResult, Token};

const ENV_PORT: &str = "PORT";

pub struct DashboardOpts {
    /// Explicit port from `--port`. `None` means "fall back to env, then 0".
    pub port: Option<u16>,
}

/// Run the dashboard until the process is signalled. Returns the process
/// exit code (0 on clean shutdown, though in practice Ctrl+C will terminate
/// the process before this returns).
pub fn run(opts: DashboardOpts) -> Result<i32> {
    let port = resolve_port(opts.port)?;
    let listener = bind(port)?;
    let bound_port = listener
        .local_addr()
        .context("failed to read bound socket address")?
        .port();

    let token = Token::generate().context("failed to read /dev/urandom for session token")?;
    eprintln!(
        "shtum dashboard listening on http://127.0.0.1:{bound_port}/?token={}",
        token.as_str()
    );
    eprintln!("press Ctrl+C to stop.");

    let server = Server::from_listener(listener, None)
        .map_err(|e| anyhow!("failed to start tiny_http server: {e}"))?;

    for request in server.incoming_requests() {
        if let Err(e) = handle(request, &token, bound_port) {
            eprintln!("[shtum dashboard] request error: {e:#}");
        }
    }
    Ok(0)
}

/// Port resolution precedence: --port flag > PORT env var > 0 (OS-picked).
fn resolve_port(flag: Option<u16>) -> Result<Option<u16>> {
    if let Some(p) = flag {
        return Ok(Some(p));
    }
    match std::env::var(ENV_PORT) {
        Ok(v) => {
            let trimmed = v.trim();
            if trimmed.is_empty() {
                return Ok(None);
            }
            let parsed: u16 = trimmed.parse().with_context(|| {
                format!("invalid PORT env var: `{trimmed}` is not a valid TCP port (0-65535)")
            })?;
            Ok(Some(parsed))
        }
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(e) => Err(e).context("failed to read PORT env var"),
    }
}

/// Bind to 127.0.0.1 with the requested port (or 0 = OS-picked). Returns a
/// clean error on port collision instead of falling back silently to a
/// random port — surprise-fallback is worse than failure for an explicit
/// request.
fn bind(port: Option<u16>) -> Result<TcpListener> {
    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port.unwrap_or(0)));
    TcpListener::bind(addr).map_err(|e| match (e.kind(), port) {
        (std::io::ErrorKind::AddrInUse, Some(p)) => anyhow!(
            "port {p} is already in use; try a different --port or unset PORT for a random one"
        ),
        (std::io::ErrorKind::PermissionDenied, Some(p)) if p < 1024 => anyhow!(
            "binding port {p} requires elevated privileges; pick a port >= 1024"
        ),
        _ => anyhow::Error::new(e).context("failed to bind 127.0.0.1"),
    })
}

/// Top-level request handler. Validates Host + token, dispatches to a route.
fn handle(request: tiny_http::Request, token: &Token, port: u16) -> Result<()> {
    let response = match auth::check_get(&request, token, port) {
        AuthResult::Ok => dispatch(&request),
        AuthResult::BadHost => error_response(421, "misdirected request"),
        AuthResult::BadToken => error_response(403, "missing or invalid token"),
    };
    request
        .respond(response)
        .context("failed to write response")?;
    Ok(())
}

fn dispatch(request: &tiny_http::Request) -> ResponseBox {
    // Strip query string for routing; we already validated the token.
    let path = request.url().split_once('?').map(|(p, _)| p).unwrap_or(request.url());
    match (request.method(), path) {
        (Method::Get, "/") => placeholder_page(),
        _ => error_response(404, "not found"),
    }
}

/// P-D1 placeholder. Replaced by the real list view in P-D2.
fn placeholder_page() -> ResponseBox {
    let body = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>shtum dashboard</title>
</head>
<body>
<h1>shtum dashboard</h1>
<p>Scaffolding online. Secret management UI lands in the next phase.</p>
</body>
</html>"#;
    html_response(200, body)
}

fn html_response(status: u16, body: &str) -> ResponseBox {
    let data = body.as_bytes().to_vec();
    let len = data.len();
    Response::new(
        StatusCode(status),
        security_headers("text/html; charset=utf-8"),
        Cursor::new(data),
        Some(len),
        None,
    )
    .boxed()
}

fn error_response(status: u16, msg: &str) -> ResponseBox {
    let body = format!(
        "<!doctype html><html><body><h1>{status}</h1><p>{}</p></body></html>",
        html_escape_minimal(msg),
    );
    html_response(status, &body)
}

/// Minimal escape for the few error strings we render in P-D1. The full
/// escape lives in `html.rs` and arrives in P-D2.
fn html_escape_minimal(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Security headers applied to every response. Locked down on purpose:
/// no scripts, no styles, no framing, no caching, no referrer.
///
/// `script-src 'unsafe-inline'` and `style-src 'unsafe-inline'` will be
/// needed in later phases for the per-row reveal/copy JS; left out here
/// because P-D1 ships no scripts.
fn security_headers(content_type: &str) -> Vec<Header> {
    vec![
        header("Content-Type", content_type),
        header(
            "Content-Security-Policy",
            "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
        ),
        header("X-Content-Type-Options", "nosniff"),
        header("Referrer-Policy", "no-referrer"),
        header("Cache-Control", "no-store"),
        header("X-Frame-Options", "DENY"),
    ]
}

fn header(name: &str, value: &str) -> Header {
    Header::from_bytes(name.as_bytes(), value.as_bytes())
        .expect("static header values are always valid")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_env<F: FnOnce() -> R, R>(key: &str, value: Option<&str>, f: F) -> R {
        // Rust tests run in parallel, but PORT is not used by other tests in
        // this module, and `cargo test` for this file is small. If this ever
        // grows we'd need a serial-test crate. For now, save/restore.
        let prev = std::env::var(key).ok();
        match value {
            Some(v) => unsafe { std::env::set_var(key, v) },
            None => unsafe { std::env::remove_var(key) },
        }
        let out = f();
        match prev {
            Some(v) => unsafe { std::env::set_var(key, v) },
            None => unsafe { std::env::remove_var(key) },
        }
        out
    }

    #[test]
    fn resolve_port_flag_wins_over_env() {
        with_env(ENV_PORT, Some("7777"), || {
            let resolved = resolve_port(Some(9999)).expect("flag should resolve");
            assert_eq!(resolved, Some(9999));
        });
    }

    #[test]
    fn resolve_port_falls_back_to_env() {
        with_env(ENV_PORT, Some("8888"), || {
            let resolved = resolve_port(None).expect("env should resolve");
            assert_eq!(resolved, Some(8888));
        });
    }

    #[test]
    fn resolve_port_defaults_to_none_when_unset() {
        with_env(ENV_PORT, None, || {
            let resolved = resolve_port(None).expect("no flag, no env → None");
            assert_eq!(resolved, None);
        });
    }

    #[test]
    fn resolve_port_rejects_bad_env() {
        with_env(ENV_PORT, Some("not-a-number"), || {
            let err = resolve_port(None).expect_err("bad env should error");
            assert!(format!("{err:#}").contains("not-a-number"));
        });
    }

    #[test]
    fn resolve_port_treats_empty_env_as_unset() {
        with_env(ENV_PORT, Some(""), || {
            let resolved = resolve_port(None).expect("empty env should be ignored");
            assert_eq!(resolved, None);
        });
    }

    #[test]
    fn bind_picks_a_free_port_with_none() {
        let listener = bind(None).expect("0 should always bind");
        let port = listener.local_addr().unwrap().port();
        assert!(port > 0);
    }

    #[test]
    fn html_escape_minimal_handles_basics() {
        assert_eq!(html_escape_minimal("<script>"), "&lt;script&gt;");
        assert_eq!(html_escape_minimal("a & b"), "a &amp; b");
    }
}
