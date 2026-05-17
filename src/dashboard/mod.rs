// Copyright 2026 Gidi Dafner
// SPDX-License-Identifier: Apache-2.0

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
use crate::temp::{self, TempRegistry};
use crate::util::shtum_exe_path;
use auth::{AuthResult, Token};
use html::{Flash, FlashKind};

/// Status code + response body. Helper functions return this tuple so the
/// top-level handler can log the status without having to pry it back out
/// of an opaque `ResponseBox`.
type Resp = (u16, ResponseBox);

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
    // Registry is opened once and reused for the lifetime of the process.
    // open_default only fails when HOME is unset, which is fatal for our
    // sweep path too — fall through to "no registry" mode (the temp-key
    // surface won't render but everything else keeps working).
    let registry = TempRegistry::open_default().ok();
    if registry.is_none() {
        eprintln!(
            "[shtum dashboard] could not open temp-key registry; \
             temp-key surface (Quick stash, TEMP badges, Extend) will be hidden"
        );
    }

    for request in server.incoming_requests() {
        if let Err(e) = handle(
            request,
            &token,
            bound_port,
            &store,
            &shtum_path,
            registry.as_ref(),
        ) {
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
///
/// A lazy temp-key sweep runs at the top of every request so expired
/// `TMP_*` entries disappear from the listing the moment a real user
/// loads the page — no daemon, no background timer.
fn handle(
    mut request: tiny_http::Request,
    token: &Token,
    port: u16,
    store: &dyn SecretStore,
    shtum_path: &str,
    registry: Option<&TempRegistry>,
) -> Result<()> {
    let method_for_log = format!("{:?}", request.method()).to_uppercase();
    let url_for_log = request.url().to_string();

    // Lazy sweep: cheap (one flock + one tiny JSON read) and keeps the
    // user-visible state honest. Errors are logged inside, never
    // propagated to the request.
    if registry.is_some() {
        temp::sweep_default(store);
    }

    let host_ok = auth::host_header(&request)
        .map(|h| auth::host_ok(h, port))
        .unwrap_or(false);
    let (status, response) = if !host_ok {
        error_response(421, "misdirected request")
    } else {
        match request.method() {
            Method::Get => match auth::check_get(&request, token, port) {
                AuthResult::Ok => dispatch_get(&request, token, store, shtum_path, registry),
                AuthResult::BadHost => error_response(421, "misdirected request"),
                AuthResult::BadToken => error_response(403, "missing or invalid token"),
            },
            Method::Post => dispatch_post(&mut request, token, store, shtum_path, registry),
            _ => error_response(405, "method not allowed"),
        }
    };

    log_request(&method_for_log, &url_for_log, status);
    request
        .respond(response)
        .context("failed to write response")?;
    Ok(())
}

/// One-line access log. Token query values are redacted, request bodies
/// are never touched (so reveal responses can't accidentally leak into
/// stderr).
fn log_request(method: &str, url: &str, status: u16) {
    eprintln!(
        "[shtum dashboard] {method} {} {status}",
        redact_token_in_url(url),
    );
}

/// Replace the value of any `token=...` query pair with `[REDACTED]`.
/// Other params (including `flash=...` after a redirect) are kept verbatim;
/// they're already percent-encoded so they're safe-to-log strings.
fn redact_token_in_url(url: &str) -> String {
    let Some((path, query)) = url.split_once('?') else {
        return url.to_string();
    };
    let mut out = String::with_capacity(url.len());
    out.push_str(path);
    out.push('?');
    let mut first = true;
    for pair in query.split('&') {
        if !first {
            out.push('&');
        }
        first = false;
        if let Some((k, _)) = pair.split_once('=') {
            if k == "token" {
                out.push_str("token=[REDACTED]");
                continue;
            }
        }
        out.push_str(pair);
    }
    out
}

/// GET dispatch. Routes the index (with optional `?flash=...` from a
/// recent redirect), the reveal endpoint for a single secret, and 404
/// otherwise.
fn dispatch_get(
    request: &tiny_http::Request,
    token: &Token,
    store: &dyn SecretStore,
    shtum_path: &str,
    registry: Option<&TempRegistry>,
) -> Resp {
    let (path, query) = split_path_query(request.url());
    match match_get_route(path) {
        GetRoute::Index => {
            let flash_owned = extract_flash(query);
            let flash = flash_owned
                .as_ref()
                .map(|(kind, msg)| Flash { kind: *kind, message: msg.as_str() });
            index_page(token, store, shtum_path, flash, registry)
        }
        GetRoute::Reveal(name) => handle_reveal(store, name),
        GetRoute::NotFound => error_response(404, "not found"),
    }
}

enum GetRoute<'a> {
    Index,
    Reveal(&'a str),
    NotFound,
}

fn match_get_route(path: &str) -> GetRoute<'_> {
    if path == "/" {
        return GetRoute::Index;
    }
    if let Some(rest) = path.strip_prefix("/secrets/") {
        if let Some(name) = rest.strip_suffix("/reveal") {
            if !name.is_empty() && !name.contains('/') {
                return GetRoute::Reveal(name);
            }
        }
    }
    GetRoute::NotFound
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
    registry: Option<&TempRegistry>,
) -> Resp {
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
        OwnedRoute::Rename(name) => handle_rename(store, &name, &form, token),
        OwnedRoute::Delete(name) => handle_delete(store, &name, token),
        OwnedRoute::Quick => handle_quick(store, registry, &form, token),
        OwnedRoute::Extend(name) => handle_extend(registry, &name, token),
        OwnedRoute::NotFound => unreachable!("guarded above"),
    }
}

enum PostRoute<'a> {
    Add,
    Rotate(&'a str),
    Rename(&'a str),
    Delete(&'a str),
    Quick,
    Extend(&'a str),
    NotFound,
}

enum OwnedRoute {
    Add,
    Rotate(String),
    Rename(String),
    Delete(String),
    Quick,
    Extend(String),
    NotFound,
}

impl PostRoute<'_> {
    fn into_owned(self) -> OwnedRoute {
        match self {
            PostRoute::Add => OwnedRoute::Add,
            PostRoute::Rotate(s) => OwnedRoute::Rotate(s.to_string()),
            PostRoute::Rename(s) => OwnedRoute::Rename(s.to_string()),
            PostRoute::Delete(s) => OwnedRoute::Delete(s.to_string()),
            PostRoute::Quick => OwnedRoute::Quick,
            PostRoute::Extend(s) => OwnedRoute::Extend(s.to_string()),
            PostRoute::NotFound => OwnedRoute::NotFound,
        }
    }
}

fn match_post_route(path: &str) -> PostRoute<'_> {
    if path == "/secrets/add" {
        return PostRoute::Add;
    }
    if path == "/secrets/quick" {
        return PostRoute::Quick;
    }
    if let Some(rest) = path.strip_prefix("/secrets/") {
        if let Some(name) = rest.strip_suffix("/rotate") {
            if !name.is_empty() && !name.contains('/') {
                return PostRoute::Rotate(name);
            }
        }
        if let Some(name) = rest.strip_suffix("/rename") {
            if !name.is_empty() && !name.contains('/') {
                return PostRoute::Rename(name);
            }
        }
        if let Some(name) = rest.strip_suffix("/delete") {
            if !name.is_empty() && !name.contains('/') {
                return PostRoute::Delete(name);
            }
        }
        if let Some(name) = rest.strip_suffix("/extend") {
            if !name.is_empty() && !name.contains('/') {
                return PostRoute::Extend(name);
            }
        }
    }
    PostRoute::NotFound
}

/// Read the request body with hard size and Content-Type guards. Returns
/// either the body bytes or a pre-formed error response.
fn read_form_body(request: &mut tiny_http::Request) -> Result<Vec<u8>, Resp> {
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
) -> Resp {
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
    let force = form
        .get("force")
        .map(|v| matches!(v.as_str(), "on" | "1" | "true"))
        .unwrap_or(false);
    match store.add(name, value, force) {
        Ok(()) => redirect_with_flash(token, FlashKind::Info, &format!("stored `{name}`")),
        Err(StoreError::AlreadyExists(n)) => redirect_with_flash(
            token,
            FlashKind::Error,
            &format!("`{n}` already exists. Refresh the page and try again — the dashboard will prompt for confirmation before overwriting."),
        ),
        Err(e) => redirect_with_flash(token, FlashKind::Error, &format!("failed to store: {e}")),
    }
}

fn handle_rotate(
    store: &dyn SecretStore,
    name_in_path: &str,
    form: &HashMap<String, String>,
    token: &Token,
) -> Resp {
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

/// Token-gated read of a single secret's value. Returns `text/plain` so
/// arbitrary stored bytes (including `<script>` or other HTML-ish data)
/// cannot be misinterpreted as a renderable document. The body is the
/// only response that carries a secret value; we never log it.
fn handle_reveal(store: &dyn SecretStore, name: &str) -> Resp {
    if let Err(e) = validate_name(name) {
        return error_response(400, &format!("{e}"));
    }
    match store.get(name) {
        Ok(value) => text_response(200, value),
        Err(StoreError::NotFound(_)) => error_response(404, "secret not found"),
        Err(e) => error_response(500, &format!("Keychain read failed: {e}")),
    }
}

/// Rename a secret. Mirrors the CLI: refuses by default if the target
/// already exists; the form's `force` checkbox lets the user opt in to
/// overwriting. The `name` hidden field must agree with the URL slug, so
/// a stale tab can't rename a different secret than the one shown.
fn handle_rename(
    store: &dyn SecretStore,
    name_in_path: &str,
    form: &HashMap<String, String>,
    token: &Token,
) -> Resp {
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
    let new_name = match form.get("new_name") {
        Some(v) if !v.is_empty() => v.as_str(),
        _ => return redirect_with_flash(token, FlashKind::Error, "new name is required"),
    };
    if let Err(e) = validate_name(new_name) {
        return redirect_with_flash(token, FlashKind::Error, &format!("{e}"));
    }
    let force = form
        .get("force")
        .map(|v| matches!(v.as_str(), "on" | "1" | "true"))
        .unwrap_or(false);
    if name_in_path == new_name {
        return redirect_with_flash(
            token,
            FlashKind::Info,
            &format!("`{name_in_path}` unchanged (old and new names are identical)"),
        );
    }
    match store.rename(name_in_path, new_name, force) {
        Ok(()) => redirect_with_flash(
            token,
            FlashKind::Info,
            &format!("renamed `{name_in_path}` -> `{new_name}`"),
        ),
        Err(StoreError::AlreadyExists(n)) => redirect_with_flash(
            token,
            FlashKind::Error,
            &format!("`{n}` already exists. Refresh the page and try again — the dashboard will prompt for confirmation before overwriting."),
        ),
        Err(StoreError::NotFound(n)) => redirect_with_flash(
            token,
            FlashKind::Error,
            &format!("`{n}` no longer exists"),
        ),
        Err(e) => redirect_with_flash(token, FlashKind::Error, &format!("failed to rename: {e}")),
    }
}

/// Quick stash from the dashboard: paste a value, get back an
/// auto-generated `TMP_*` name + 4h-idle TTL (or the user's `ttl` if
/// supplied). Mirrors the CLI's `shtum quick` semantics.
fn handle_quick(
    store: &dyn SecretStore,
    registry: Option<&TempRegistry>,
    form: &HashMap<String, String>,
    token: &Token,
) -> Resp {
    let Some(registry) = registry else {
        return redirect_with_flash(
            token,
            FlashKind::Error,
            "temp-key registry is unavailable — Quick stash is disabled",
        );
    };
    let value = match form.get("value") {
        Some(v) if !v.is_empty() => v.as_bytes(),
        _ => return redirect_with_flash(token, FlashKind::Error, "value is required"),
    };
    let ttl = match form.get("ttl").map(|s| s.trim()).filter(|s| !s.is_empty()) {
        Some(s) => match temp::parse_ttl(s) {
            Ok(d) => d,
            Err(e) => return redirect_with_flash(token, FlashKind::Error, &e),
        },
        None => std::time::Duration::from_secs(temp::DEFAULT_TTL_SECONDS),
    };

    // Generate-and-add with collision retry — same logic as the CLI.
    let mut last_err: Option<StoreError> = None;
    let mut chosen: Option<String> = None;
    for _ in 0..10 {
        let candidate = match temp::generate_temp_name() {
            Ok(n) => n,
            Err(e) => {
                return redirect_with_flash(
                    token,
                    FlashKind::Error,
                    &format!("failed to generate temp-key name: {e}"),
                );
            }
        };
        match store.add(&candidate, value, false) {
            Ok(()) => {
                chosen = Some(candidate);
                break;
            }
            Err(StoreError::AlreadyExists(_)) => continue,
            Err(e) => {
                last_err = Some(e);
                break;
            }
        }
    }
    let name = match chosen {
        Some(n) => n,
        None => {
            let msg = match last_err {
                Some(e) => format!("failed to store temp value: {e}"),
                None => "could not find an unused TMP_* name after 10 attempts".to_string(),
            };
            return redirect_with_flash(token, FlashKind::Error, &msg);
        }
    };

    if let Err(e) = registry.register(&name, ttl) {
        // Roll back the Keychain entry so we don't leave an unregistered
        // TMP_* lying around. Best effort — log if even the rollback fails.
        if let Err(re) = store.delete(&name) {
            eprintln!(
                "[shtum dashboard] failed to roll back `{name}` after registry error: {re}"
            );
        }
        return redirect_with_flash(
            token,
            FlashKind::Error,
            &format!("failed to register temp key: {e}"),
        );
    }

    redirect_with_flash(
        token,
        FlashKind::Info,
        &format!(
            "stashed `{name}`, expires after {} idle",
            temp::format_duration_compact(ttl),
        ),
    )
}

/// Dashboard "Extend" button: bump `last_used_at` to now. Returns a
/// flash either way — succeeds quietly for tracked names, complains
/// when called for an unknown name (likely a stale tab).
fn handle_extend(
    registry: Option<&TempRegistry>,
    name_in_path: &str,
    token: &Token,
) -> Resp {
    if let Err(e) = validate_name(name_in_path) {
        return redirect_with_flash(token, FlashKind::Error, &format!("{e}"));
    }
    let Some(registry) = registry else {
        return redirect_with_flash(
            token,
            FlashKind::Error,
            "temp-key registry is unavailable — Extend is disabled",
        );
    };
    match registry.extend(name_in_path) {
        Ok(true) => redirect_with_flash(
            token,
            FlashKind::Info,
            &format!("extended `{name_in_path}`"),
        ),
        Ok(false) => redirect_with_flash(
            token,
            FlashKind::Error,
            &format!("`{name_in_path}` is not a tracked temp key"),
        ),
        Err(e) => redirect_with_flash(
            token,
            FlashKind::Error,
            &format!("failed to extend: {e}"),
        ),
    }
}

fn handle_delete(store: &dyn SecretStore, name_in_path: &str, token: &Token) -> Resp {
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
fn redirect_with_flash(token: &Token, kind: FlashKind, message: &str) -> Resp {
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
    let response = Response::new(
        StatusCode(303),
        headers,
        Cursor::new(data),
        Some(len),
        None,
    )
    .boxed();
    (303, response)
}

/// Render the dashboard index. Keychain read failures show an inline error
/// rather than crashing the loop.
fn index_page(
    token: &Token,
    store: &dyn SecretStore,
    shtum_path: &str,
    flash: Option<Flash<'_>>,
    registry: Option<&TempRegistry>,
) -> Resp {
    let secrets = match store.list() {
        Ok(names) => names,
        Err(e) => {
            return error_response(
                500,
                &format!("failed to list secrets from Keychain: {e}"),
            );
        }
    };
    let temp_entries: Vec<html::TempEntryView> = registry
        .map(|r| {
            r.snapshot()
                .into_iter()
                .map(|e| html::TempEntryView {
                    expires_at: e.expires_at(),
                    name: e.name,
                })
                .collect()
        })
        .unwrap_or_default();
    let body = html::list_page(
        &secrets,
        &temp_entries,
        token.as_str(),
        shtum_path,
        flash,
    );
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

fn html_response(status: u16, body: &str) -> Resp {
    let data = body.as_bytes().to_vec();
    let len = data.len();
    let response = Response::new(
        StatusCode(status),
        security_headers("text/html; charset=utf-8"),
        Cursor::new(data),
        Some(len),
        None,
    )
    .boxed();
    (status, response)
}

/// Plain-text response used for the reveal endpoint. Sniff-proof so a
/// stored value containing `<script>` can't be misinterpreted as HTML by
/// a misconfigured browser.
fn text_response(status: u16, body: Vec<u8>) -> Resp {
    let len = body.len();
    let response = Response::new(
        StatusCode(status),
        security_headers("text/plain; charset=utf-8"),
        Cursor::new(body),
        Some(len),
        None,
    )
    .boxed();
    (status, response)
}

fn error_response(status: u16, msg: &str) -> Resp {
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
            "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
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
    fn match_post_route_rename_extracts_name() {
        match match_post_route("/secrets/MY_KEY/rename") {
            PostRoute::Rename("MY_KEY") => {}
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
        assert!(matches!(
            match_post_route("/secrets/foo/bar/rename"),
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
        assert!(matches!(
            match_post_route("/secrets//rename"),
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
            PostRoute::Rename(n) => format!("Rename({n})"),
            PostRoute::Delete(n) => format!("Delete({n})"),
            PostRoute::Quick => "Quick".into(),
            PostRoute::Extend(n) => format!("Extend({n})"),
            PostRoute::NotFound => "NotFound".into(),
        }
    }

    #[test]
    fn match_post_route_quick_exact() {
        assert!(matches!(match_post_route("/secrets/quick"), PostRoute::Quick));
    }

    #[test]
    fn match_post_route_extend_extracts_name() {
        match match_post_route("/secrets/TMP_abc123/extend") {
            PostRoute::Extend("TMP_abc123") => {}
            other => panic!("unexpected: {}", debug_route(&other)),
        }
    }

    #[test]
    fn match_post_route_extend_rejects_empty_or_nested() {
        assert!(matches!(
            match_post_route("/secrets//extend"),
            PostRoute::NotFound,
        ));
        assert!(matches!(
            match_post_route("/secrets/foo/bar/extend"),
            PostRoute::NotFound,
        ));
    }
}
