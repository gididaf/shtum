//! Local web dashboard for managing stored secrets and viewing hook-install
//! snippets. Binds 127.0.0.1 only; gated by a random session token. Runs
//! until the process is interrupted (Ctrl+C exits the loop).
//!
//! P-D3 milestone: add / rotate / delete forms. Reveal endpoint and copy
//! buttons land in P-D4.

mod auth;
mod form;
mod html;

use std::collections::HashMap;
use std::io::{Cursor, Read};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener};

use anyhow::{Context, Result, anyhow};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use tiny_http::{Header, Method, Response, ResponseBox, Server, StatusCode};

use crate::store::{SecretStore, StoreError, default_store, validate_name};
use crate::util::shtum_exe_path;
use auth::{AuthResult, Token};
use html::{Flash, FlashKind};

const ENV_PORT: &str = "PORT";
/// Hard cap on a single POST body. Plenty for a name + value + token; a
/// well-behaved client can't bury us in memory by sending GBs.
const MAX_BODY_BYTES: usize = 64 * 1024;
/// Required Content-Type for all POSTs. Reject anything else with 415.
const FORM_CONTENT_TYPE: &str = "application/x-www-form-urlencoded";

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

    let store = default_store();
    let shtum_path = shtum_exe_path().unwrap_or_else(|_| "shtum".to_string());

    for request in server.incoming_requests() {
        if let Err(e) = handle(request, &token, bound_port, &store, &shtum_path) {
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

/// Top-level request handler.
///
/// GET requests: Host check + token from query string, then dispatch.
/// POST requests: Host check only; each POST handler reads the body and
/// verifies the token from the form fields (cookie-free CSRF protection).
fn handle(
    mut request: tiny_http::Request,
    token: &Token,
    port: u16,
    store: &dyn SecretStore,
    shtum_path: &str,
) -> Result<()> {
    let host_ok = auth::host_header(&request)
        .map(|h| auth::host_ok(h, port))
        .unwrap_or(false);
    if !host_ok {
        return respond(request, error_response(421, "misdirected request"));
    }

    let response = match request.method() {
        Method::Get => {
            // Token must be in URL for GETs.
            match auth::check_get(&request, token, port) {
                AuthResult::Ok => dispatch_get(&request, token, store, shtum_path),
                AuthResult::BadHost => error_response(421, "misdirected request"),
                AuthResult::BadToken => error_response(403, "missing or invalid token"),
            }
        }
        Method::Post => dispatch_post(&mut request, token, store, shtum_path),
        _ => error_response(405, "method not allowed"),
    };

    respond(request, response)
}

fn respond(request: tiny_http::Request, response: ResponseBox) -> Result<()> {
    request
        .respond(response)
        .context("failed to write response")?;
    Ok(())
}

/// GET dispatch. Routes the index (with optional `?flash=...` from a recent
/// redirect) and refuses everything else.
fn dispatch_get(
    request: &tiny_http::Request,
    token: &Token,
    store: &dyn SecretStore,
    shtum_path: &str,
) -> ResponseBox {
    let (path, query) = split_path_query(request.url());
    match path {
        "/" => {
            let flash_owned = extract_flash(query);
            let flash = flash_owned
                .as_ref()
                .map(|(kind, msg)| Flash { kind: *kind, message: msg.as_str() });
            index_page(token, store, shtum_path, flash)
        }
        _ => error_response(404, "not found"),
    }
}

/// POST dispatch. Reads the body up to [`MAX_BODY_BYTES`], rejects anything
/// without `Content-Type: application/x-www-form-urlencoded` (415),
/// over-length bodies (413), or malformed forms (400). All mutation
/// handlers receive the parsed form map and verify the embedded token
/// before touching the Keychain.
fn dispatch_post(
    request: &mut tiny_http::Request,
    token: &Token,
    store: &dyn SecretStore,
    _shtum_path: &str,
) -> ResponseBox {
    // Resolve the route into an owned variant first so the immutable
    // borrow of `request.url()` is gone before we read the body.
    let (path, _query) = split_path_query(request.url());
    let route = match_post_route(path).into_owned();

    if matches!(route, OwnedRoute::NotFound) {
        return error_response(404, "not found");
    }

    let body = match read_form_body(request) {
        Ok(b) => b,
        Err(resp) => return resp,
    };
    let form = match form::parse_strict(&body) {
        Ok(f) => f,
        Err(e) => return error_response(400, &format!("malformed form: {e}")),
    };

    if !form
        .get("token")
        .map(|v| token.verify(v))
        .unwrap_or(false)
    {
        return error_response(403, "missing or invalid token");
    }

    match route {
        OwnedRoute::Add => handle_add(store, &form, token),
        OwnedRoute::Rotate(name) => handle_rotate(store, &name, &form, token),
        OwnedRoute::Delete(name) => handle_delete(store, &name, token),
        OwnedRoute::NotFound => unreachable!("guarded above"),
    }
}

enum PostRoute<'a> {
    Add,
    Rotate(&'a str),
    Delete(&'a str),
    NotFound,
}

enum OwnedRoute {
    Add,
    Rotate(String),
    Delete(String),
    NotFound,
}

impl PostRoute<'_> {
    fn into_owned(self) -> OwnedRoute {
        match self {
            PostRoute::Add => OwnedRoute::Add,
            PostRoute::Rotate(s) => OwnedRoute::Rotate(s.to_string()),
            PostRoute::Delete(s) => OwnedRoute::Delete(s.to_string()),
            PostRoute::NotFound => OwnedRoute::NotFound,
        }
    }
}

fn match_post_route(path: &str) -> PostRoute<'_> {
    if path == "/secrets/add" {
        return PostRoute::Add;
    }
    if let Some(rest) = path.strip_prefix("/secrets/") {
        if let Some(name) = rest.strip_suffix("/rotate") {
            if !name.is_empty() && !name.contains('/') {
                return PostRoute::Rotate(name);
            }
        }
        if let Some(name) = rest.strip_suffix("/delete") {
            if !name.is_empty() && !name.contains('/') {
                return PostRoute::Delete(name);
            }
        }
    }
    PostRoute::NotFound
}

/// Read the request body with hard size and Content-Type guards. Returns
/// either the body bytes or a pre-formed error response.
fn read_form_body(request: &mut tiny_http::Request) -> Result<Vec<u8>, ResponseBox> {
    let ct_ok = request.headers().iter().any(|h| {
        h.field.as_str().as_str().eq_ignore_ascii_case("content-type")
            && h.value
                .as_str()
                .split(';')
                .next()
                .map(|t| t.trim().eq_ignore_ascii_case(FORM_CONTENT_TYPE))
                .unwrap_or(false)
    });
    if !ct_ok {
        return Err(error_response(
            415,
            "expected Content-Type: application/x-www-form-urlencoded",
        ));
    }

    if let Some(declared) = request.body_length() {
        if declared > MAX_BODY_BYTES {
            return Err(error_response(413, "request body too large"));
        }
    }

    // Read up to MAX_BODY_BYTES + 1; if we hit the cap, fail.
    let cap = (MAX_BODY_BYTES + 1) as u64;
    let mut body = Vec::new();
    if let Err(e) = request.as_reader().take(cap).read_to_end(&mut body) {
        return Err(error_response(
            400,
            &format!("failed to read request body: {e}"),
        ));
    }
    if body.len() > MAX_BODY_BYTES {
        return Err(error_response(413, "request body too large"));
    }
    Ok(body)
}

fn handle_add(
    store: &dyn SecretStore,
    form: &HashMap<String, String>,
    token: &Token,
) -> ResponseBox {
    let name = match form.get("name") {
        Some(n) if !n.is_empty() => n,
        _ => return redirect_with_flash(token, FlashKind::Error, "name is required"),
    };
    let value = match form.get("value") {
        Some(v) if !v.is_empty() => v.as_bytes(),
        _ => return redirect_with_flash(token, FlashKind::Error, "value is required"),
    };
    if let Err(e) = validate_name(name) {
        return redirect_with_flash(token, FlashKind::Error, &format!("{e}"));
    }
    match store.set(name, value) {
        Ok(()) => redirect_with_flash(token, FlashKind::Info, &format!("stored `{name}`")),
        Err(e) => redirect_with_flash(token, FlashKind::Error, &format!("failed to store: {e}")),
    }
}

fn handle_rotate(
    store: &dyn SecretStore,
    name_in_path: &str,
    form: &HashMap<String, String>,
    token: &Token,
) -> ResponseBox {
    // The form also includes a `name` field; require they agree so a stale
    // tab can't rotate a different secret than the one shown.
    if let Some(form_name) = form.get("name") {
        if form_name != name_in_path {
            return redirect_with_flash(
                token,
                FlashKind::Error,
                "form name does not match URL — refresh and try again",
            );
        }
    }
    if let Err(e) = validate_name(name_in_path) {
        return redirect_with_flash(token, FlashKind::Error, &format!("{e}"));
    }
    let value = match form.get("value") {
        Some(v) if !v.is_empty() => v.as_bytes(),
        _ => return redirect_with_flash(token, FlashKind::Error, "value is required"),
    };
    // Rotate = delete + set, mirroring the CLI. Missing entries on the
    // delete step are fine (the CLI treats that as the no-op success path).
    match store.delete(name_in_path) {
        Ok(()) | Err(StoreError::NotFound(_)) => {}
        Err(e) => {
            return redirect_with_flash(
                token,
                FlashKind::Error,
                &format!("failed to rotate: {e}"),
            );
        }
    }
    match store.set(name_in_path, value) {
        Ok(()) => redirect_with_flash(
            token,
            FlashKind::Info,
            &format!("rotated `{name_in_path}`"),
        ),
        Err(e) => redirect_with_flash(token, FlashKind::Error, &format!("failed to rotate: {e}")),
    }
}

fn handle_delete(store: &dyn SecretStore, name_in_path: &str, token: &Token) -> ResponseBox {
    if let Err(e) = validate_name(name_in_path) {
        return redirect_with_flash(token, FlashKind::Error, &format!("{e}"));
    }
    match store.delete(name_in_path) {
        Ok(()) => redirect_with_flash(token, FlashKind::Info, &format!("deleted `{name_in_path}`")),
        Err(StoreError::NotFound(_)) => redirect_with_flash(
            token,
            FlashKind::Info,
            &format!("`{name_in_path}` was already gone"),
        ),
        Err(e) => redirect_with_flash(token, FlashKind::Error, &format!("failed to delete: {e}")),
    }
}

/// 303 redirect back to `/` with the session token preserved and a flash
/// message encoded into the query string. 303 is correct for "after a
/// successful POST, send the client to a GET" — the browser will not
/// re-submit the form if the user reloads the destination.
fn redirect_with_flash(token: &Token, kind: FlashKind, message: &str) -> ResponseBox {
    let kind_param = match kind {
        FlashKind::Info => "info",
        FlashKind::Error => "error",
    };
    let location = format!(
        "/?token={}&flash_kind={}&flash={}",
        utf8_percent_encode(token.as_str(), NON_ALPHANUMERIC),
        kind_param,
        utf8_percent_encode(message, NON_ALPHANUMERIC),
    );
    let mut headers = security_headers("text/plain; charset=utf-8");
    headers.push(header("Location", &location));
    let body = "redirecting...";
    let data = body.as_bytes().to_vec();
    let len = data.len();
    Response::new(
        StatusCode(303),
        headers,
        Cursor::new(data),
        Some(len),
        None,
    )
    .boxed()
}

/// Render the dashboard index. Keychain read failures show an inline error
/// rather than crashing the loop.
fn index_page(
    token: &Token,
    store: &dyn SecretStore,
    shtum_path: &str,
    flash: Option<Flash<'_>>,
) -> ResponseBox {
    let secrets = match store.list() {
        Ok(names) => names,
        Err(e) => {
            return error_response(
                500,
                &format!("failed to list secrets from Keychain: {e}"),
            );
        }
    };
    let body = html::list_page(&secrets, token.as_str(), shtum_path, flash);
    html_response(200, &body)
}

/// Pull `flash` + `flash_kind` out of the query string. Either being
/// absent or malformed silently drops the flash — never block on it.
/// Returns owned data so the caller can build a borrowed `Flash<'_>`
/// without leaking heap memory across requests.
fn extract_flash(query: Option<&str>) -> Option<(FlashKind, String)> {
    let q = query?;
    let mut message: Option<String> = None;
    let mut kind = FlashKind::Info;
    for pair in q.split('&') {
        let Some((k, v)) = pair.split_once('=') else {
            continue;
        };
        let decoded = match percent_encoding::percent_decode_str(v).decode_utf8() {
            Ok(c) => c.into_owned(),
            Err(_) => continue,
        };
        match k {
            "flash" => message = Some(decoded),
            "flash_kind" if decoded == "error" => kind = FlashKind::Error,
            _ => {}
        }
    }
    message.map(|m| (kind, m))
}

fn split_path_query(url: &str) -> (&str, Option<&str>) {
    match url.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (url, None),
    }
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
    let body = html::error_page(status, msg);
    html_response(status, &body)
}

/// Security headers applied to every response.
///
/// `style-src 'unsafe-inline'` covers our `<style>` block; `script-src
/// 'unsafe-inline'` covers the inline `onsubmit="return confirm(...)"` on
/// the delete button and the reveal/copy JS that lands in P-D4. Stored
/// secret values are never rendered into HTML (the reveal endpoint will
/// send `text/plain` in P-D4 and JS will assign via `textContent`), so
/// opening inline-script doesn't expose them as an XSS sink.
fn security_headers(content_type: &str) -> Vec<Header> {
    vec![
        header("Content-Type", content_type),
        header(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
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
    fn match_post_route_add_exact() {
        assert!(matches!(match_post_route("/secrets/add"), PostRoute::Add));
    }

    #[test]
    fn match_post_route_rotate_extracts_name() {
        match match_post_route("/secrets/MY_KEY/rotate") {
            PostRoute::Rotate("MY_KEY") => {}
            other => panic!("unexpected: {}", debug_route(&other)),
        }
    }

    #[test]
    fn match_post_route_delete_extracts_name() {
        match match_post_route("/secrets/MY_KEY/delete") {
            PostRoute::Delete("MY_KEY") => {}
            other => panic!("unexpected: {}", debug_route(&other)),
        }
    }

    #[test]
    fn match_post_route_rejects_nested_slash() {
        // Path-traversal attempt or accidental nested segment.
        assert!(matches!(
            match_post_route("/secrets/foo/bar/delete"),
            PostRoute::NotFound,
        ));
    }

    #[test]
    fn match_post_route_rejects_empty_name() {
        assert!(matches!(
            match_post_route("/secrets//rotate"),
            PostRoute::NotFound,
        ));
        assert!(matches!(
            match_post_route("/secrets//delete"),
            PostRoute::NotFound,
        ));
    }

    #[test]
    fn match_post_route_unknown_returns_not_found() {
        assert!(matches!(
            match_post_route("/something-else"),
            PostRoute::NotFound,
        ));
    }

    #[test]
    fn extract_flash_decodes_message_and_kind() {
        let q = Some("token=abc&flash=stored%20FOO&flash_kind=info");
        let got = extract_flash(q).expect("flash should parse");
        assert!(matches!(got.0, FlashKind::Info));
        assert_eq!(got.1, "stored FOO");
    }

    #[test]
    fn extract_flash_detects_error_kind() {
        let q = Some("flash=oops&flash_kind=error");
        let got = extract_flash(q).expect("flash should parse");
        assert!(matches!(got.0, FlashKind::Error));
        assert_eq!(got.1, "oops");
    }

    #[test]
    fn extract_flash_absent_when_no_flash_param() {
        assert!(extract_flash(Some("token=abc")).is_none());
        assert!(extract_flash(None).is_none());
    }

    fn debug_route(r: &PostRoute<'_>) -> String {
        match r {
            PostRoute::Add => "Add".into(),
            PostRoute::Rotate(n) => format!("Rotate({n})"),
            PostRoute::Delete(n) => format!("Delete({n})"),
            PostRoute::NotFound => "NotFound".into(),
        }
    }
}
