//! HTML rendering for the dashboard. Server-rendered, no template engine,
//! no SPA — page strings are assembled from `format!()` with all
//! interpolated user content passed through [`escape`].

/// HTML-escape the five characters that have semantic meaning in HTML5
/// element bodies and double/single-quoted attribute values: `& < > " '`.
///
/// Order matters: `&` must be replaced first, otherwise the entities we
/// emit for the other characters would themselves get double-encoded.
///
/// Allocates only when a replacement is required; pure ASCII inputs with
/// none of the metacharacters return without copying.
pub fn escape(s: &str) -> String {
    if !s.bytes().any(|b| matches!(b, b'&' | b'<' | b'>' | b'"' | b'\'')) {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// Severity hint for the flash banner.
#[derive(Debug, Clone, Copy)]
pub enum FlashKind {
    Info,
    Error,
}

pub struct Flash<'a> {
    pub kind: FlashKind,
    pub message: &'a str,
}

/// Render the dashboard index. The session token is embedded in every
/// form as a hidden field so each POST can be verified server-side
/// without relying on cookies.
pub fn list_page(
    secrets: &[String],
    token: &str,
    shtum_path: &str,
    flash: Option<Flash<'_>>,
) -> String {
    let flash_html = flash
        .map(|f| {
            let class = match f.kind {
                FlashKind::Info => "flash",
                FlashKind::Error => "flash error",
            };
            format!(r#"<div class="{}">{}</div>"#, class, escape(f.message))
        })
        .unwrap_or_default();

    let token_esc = escape(token);

    let add_form = format!(
        r#"<form class="add-form" action="/secrets/add" method="post" autocomplete="off">
<input type="hidden" name="token" value="{token}">
<label>Name <input type="text" name="name" placeholder="MY_SECRET" required pattern="[A-Za-z0-9_.\-]+"></label>
<label>Value <input type="password" name="value" placeholder="(hidden)" required></label>
<button type="submit">Add</button>
</form>"#,
        token = token_esc,
    );

    let secrets_section = if secrets.is_empty() {
        format!(
            r#"<p class="muted">No secrets stored yet. Add one above, or via <code>shtum store add &lt;NAME&gt;</code> from your terminal.</p>
{add_form}"#,
        )
    } else {
        let rows: String = secrets
            .iter()
            .map(|name| render_secret_row(name, &token_esc))
            .collect();
        format!(
            r#"{add_form}
<table class="secrets">
<thead><tr><th>Name</th><th>Actions</th></tr></thead>
<tbody>
{rows}
</tbody>
</table>"#,
        )
    };

    let global_cmd = format!("{} hook install", shtum_path);
    let project_cmd = format!(
        "cd /path/to/your-project && {} hook install --project",
        shtum_path,
    );

    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>shtum dashboard</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, sans-serif; max-width: 920px; margin: 2rem auto; padding: 0 1rem; color: #222; }}
h1 {{ margin-top: 0; }}
h2 {{ margin-top: 2.5rem; border-bottom: 1px solid #ddd; padding-bottom: 0.25rem; }}
table.secrets {{ width: 100%; border-collapse: collapse; margin-top: 0.5rem; }}
table.secrets th, table.secrets td {{ text-align: left; padding: 0.5rem 0.75rem; border-bottom: 1px solid #eee; vertical-align: middle; }}
table.secrets th {{ font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em; color: #555; }}
td.name {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }}
td.actions {{ display: flex; gap: 0.5rem; flex-wrap: wrap; align-items: center; }}
.muted {{ color: #888; }}
pre.snippet {{ background: #f5f5f5; border: 1px solid #e0e0e0; padding: 0.75rem 1rem; border-radius: 4px; overflow-x: auto; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.9rem; }}
.flash {{ background: #fff8c4; border: 1px solid #e6d878; padding: 0.5rem 0.75rem; border-radius: 4px; margin-bottom: 1rem; }}
.flash.error {{ background: #fde4e4; border-color: #e3a0a0; color: #802020; }}
.hint {{ color: #555; font-size: 0.9rem; }}
form.add-form {{ background: #f8f8f8; padding: 0.75rem 1rem; border-radius: 4px; margin: 0.5rem 0 1rem; display: flex; gap: 0.75rem; align-items: center; flex-wrap: wrap; }}
form.add-form label {{ display: flex; gap: 0.25rem; align-items: center; font-size: 0.9rem; color: #444; }}
form.inline {{ display: inline-flex; gap: 0.25rem; align-items: center; margin: 0; }}
input[type=text], input[type=password] {{ padding: 0.3rem 0.5rem; border: 1px solid #ccc; border-radius: 3px; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.9rem; }}
button {{ padding: 0.3rem 0.8rem; border: 1px solid #888; background: #f7f7f7; cursor: pointer; border-radius: 3px; font-size: 0.85rem; color: #222; }}
button:hover {{ background: #ececec; }}
button.danger {{ color: #802020; border-color: #d99; background: #fff5f5; }}
button.danger:hover {{ background: #fde4e4; }}
.value-display {{ display: none; padding: 0.25rem 0.5rem; background: #fffbe0; border: 1px solid #e6d878; border-radius: 3px; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.85rem; word-break: break-all; max-width: 320px; }}
.value-display.shown {{ display: inline-block; }}
.snippet-wrap {{ position: relative; }}
.snippet-wrap button.copy-btn {{ position: absolute; top: 0.5rem; right: 0.5rem; font-size: 0.75rem; padding: 0.2rem 0.6rem; }}
</style>
</head>
<body data-token="{token}">
<h1>shtum dashboard</h1>
{flash_html}

<h2>Stored secrets</h2>
{secrets_section}

<h2>Install the Claude Code hook</h2>
<p class="hint">These commands install the PreToolUse hook that rewrites Bash tool calls containing <code>{{NAME}}</code> placeholders through <code>shtum run</code>. Pick one:</p>

<p><strong>Global</strong> (writes to <code>~/.claude/settings.json</code>, applies to every project):</p>
<div class="snippet-wrap">
<pre class="snippet" id="snippet-global">{}</pre>
<button type="button" class="copy-btn" data-action="copy" data-target="snippet-global">Copy</button>
</div>

<p><strong>Per-project</strong> (writes to <code>./.claude/settings.json</code> in the directory you run it from):</p>
<div class="snippet-wrap">
<pre class="snippet" id="snippet-project">{}</pre>
<button type="button" class="copy-btn" data-action="copy" data-target="snippet-project">Copy</button>
</div>
<p class="hint">Replace <code>/path/to/your-project</code> with the project directory you want to enable.</p>

<script>
(function() {{
  var token = document.body.dataset.token;
  document.addEventListener('click', function(e) {{
    var btn = e.target.closest('[data-action]');
    if (!btn) return;
    var action = btn.dataset.action;
    if (action === 'reveal') return revealOrHide(btn);
    if (action === 'copy') return copySnippet(btn);
  }});
  function revealOrHide(btn) {{
    var cell = btn.parentElement.querySelector('.value-display');
    if (!cell) return;
    if (btn.dataset.shown === '1') {{ hide(btn, cell); return; }}
    var name = btn.dataset.name;
    fetch('/secrets/' + encodeURIComponent(name) + '/reveal?token=' + encodeURIComponent(token))
      .then(function(r) {{ if (!r.ok) throw new Error('HTTP ' + r.status); return r.text(); }})
      .then(function(value) {{
        cell.textContent = value;
        cell.classList.add('shown');
        btn.textContent = 'Hide';
        btn.dataset.shown = '1';
        if (btn._t) clearTimeout(btn._t);
        btn._t = setTimeout(function() {{ hide(btn, cell); }}, 30000);
      }})
      .catch(function(err) {{ alert('reveal failed: ' + err.message); }});
  }}
  function hide(btn, cell) {{
    cell.textContent = '';
    cell.classList.remove('shown');
    btn.textContent = 'Reveal';
    btn.dataset.shown = '';
    if (btn._t) {{ clearTimeout(btn._t); btn._t = null; }}
  }}
  function copySnippet(btn) {{
    var target = document.getElementById(btn.dataset.target);
    if (!target) return;
    var text = target.textContent;
    if (!navigator.clipboard) {{ alert('clipboard API unavailable'); return; }}
    navigator.clipboard.writeText(text).then(function() {{
      var orig = btn.dataset.orig || btn.textContent;
      btn.dataset.orig = orig;
      btn.textContent = 'Copied!';
      setTimeout(function() {{ btn.textContent = orig; }}, 1500);
    }}).catch(function(err) {{ alert('copy failed: ' + err.message); }});
  }}
}})();
</script>
</body>
</html>"#,
        escape(&global_cmd),
        escape(&project_cmd),
        token = token_esc,
    )
}

/// Render a single `<tr>` for a secret. Reveal/Hide is wired up via
/// event-delegation in the page-level script — no inline `onclick`
/// attributes. The delete form keeps an inline `onsubmit` confirm() so
/// the prompt fires even if the page-level JS errored out for some
/// reason.
fn render_secret_row(name: &str, token_esc: &str) -> String {
    let name_esc = escape(name);
    let confirm_msg = escape(&format!(
        "Delete \"{name}\" from the Keychain? This cannot be undone.",
    ));
    format!(
        r#"<tr><td class="name">{name_esc}</td><td class="actions">
<button type="button" class="reveal-btn" data-action="reveal" data-name="{name_esc}">Reveal</button>
<span class="value-display"></span>
<form class="inline" action="/secrets/{name_esc}/rotate" method="post" autocomplete="off">
<input type="hidden" name="token" value="{token_esc}">
<input type="hidden" name="name" value="{name_esc}">
<input type="password" name="value" placeholder="new value" required>
<button type="submit">Rotate</button>
</form>
<form class="inline" action="/secrets/{name_esc}/delete" method="post" onsubmit="return confirm('{confirm_msg}');">
<input type="hidden" name="token" value="{token_esc}">
<input type="hidden" name="name" value="{name_esc}">
<button type="submit" class="danger">Delete</button>
</form>
</td></tr>"#,
    )
}

/// Minimal error page for non-200 responses.
pub fn error_page(status: u16, msg: &str) -> String {
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{status} — shtum dashboard</title>
<style>body {{ font-family: -apple-system, BlinkMacSystemFont, sans-serif; max-width: 600px; margin: 4rem auto; padding: 0 1rem; }}</style>
</head>
<body>
<h1>{status}</h1>
<p>{}</p>
</body>
</html>"#,
        escape(msg),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_handles_all_five_metachars() {
        assert_eq!(escape("<script>"), "&lt;script&gt;");
        assert_eq!(escape("a & b"), "a &amp; b");
        assert_eq!(escape(r#"say "hi""#), "say &quot;hi&quot;");
        assert_eq!(escape("it's"), "it&#39;s");
        assert_eq!(
            escape(r#"<a href="x" title='y'>&"#),
            "&lt;a href=&quot;x&quot; title=&#39;y&#39;&gt;&amp;",
        );
    }

    #[test]
    fn escape_amp_first_prevents_double_encoding() {
        assert_eq!(escape("&lt;"), "&amp;lt;");
    }

    #[test]
    fn escape_passes_through_safe_input_unchanged() {
        assert_eq!(escape("FOO_BAR.baz-1"), "FOO_BAR.baz-1");
        assert_eq!(escape(""), "");
        assert_eq!(escape("hello, world"), "hello, world");
    }

    #[test]
    fn list_page_empty_state_renders_friendly_message_and_add_form() {
        let html = list_page(&[], "tok", "/usr/local/bin/shtum", None);
        assert!(html.contains("No secrets stored yet"));
        assert!(!html.contains("<tbody>"));
        assert!(html.contains(r#"action="/secrets/add""#));
    }

    #[test]
    fn list_page_renders_per_row_rotate_and_delete_forms() {
        let names = vec!["AWS_KEY".to_string(), "GH_TOKEN".to_string()];
        let html = list_page(&names, "tok", "/usr/local/bin/shtum", None);
        assert!(html.contains(r#"action="/secrets/AWS_KEY/rotate""#));
        assert!(html.contains(r#"action="/secrets/AWS_KEY/delete""#));
        assert!(html.contains(r#"action="/secrets/GH_TOKEN/rotate""#));
        assert!(html.contains(r#"action="/secrets/GH_TOKEN/delete""#));
    }

    #[test]
    fn list_page_embeds_token_in_every_form() {
        let names = vec!["FOO".to_string()];
        let html = list_page(&names, "TESTTOKEN", "/usr/local/bin/shtum", None);
        // Add form, rotate form, delete form — three hidden token inputs
        // (plus one for any flash, but flash doesn't contain it).
        let count = html.matches(r#"name="token" value="TESTTOKEN""#).count();
        assert_eq!(count, 3, "expected 3 hidden token inputs, found {count}");
    }

    #[test]
    fn list_page_delete_form_has_confirm() {
        let names = vec!["DANGEROUS".to_string()];
        let html = list_page(&names, "tok", "/usr/local/bin/shtum", None);
        assert!(html.contains(r#"onsubmit="return confirm("#));
        assert!(html.contains("DANGEROUS"));
    }

    #[test]
    fn list_page_renders_hook_snippets() {
        let html = list_page(&[], "tok", "/abs/path/to/shtum", None);
        assert!(html.contains("/abs/path/to/shtum hook install"));
        assert!(html.contains("cd /path/to/your-project &amp;&amp; /abs/path/to/shtum hook install --project"));
    }

    #[test]
    fn list_page_escapes_shtum_path_with_meta() {
        let html = list_page(&[], "tok", "/weird/<path>/shtum", None);
        assert!(!html.contains("/weird/<path>/shtum"));
        assert!(html.contains("/weird/&lt;path&gt;/shtum"));
    }

    #[test]
    fn list_page_renders_info_flash() {
        let flash = Flash { kind: FlashKind::Info, message: "stored FOO" };
        let html = list_page(&[], "tok", "/usr/local/bin/shtum", Some(flash));
        assert!(html.contains(r#"class="flash""#));
        assert!(html.contains("stored FOO"));
    }

    #[test]
    fn list_page_renders_error_flash_with_distinct_class() {
        let flash = Flash { kind: FlashKind::Error, message: "name rejected" };
        let html = list_page(&[], "tok", "/usr/local/bin/shtum", Some(flash));
        assert!(html.contains(r#"class="flash error""#));
        assert!(html.contains("name rejected"));
    }

    #[test]
    fn list_page_omits_flash_div_when_absent() {
        let html = list_page(&[], "tok", "/usr/local/bin/shtum", None);
        assert!(!html.contains(r#"class="flash""#));
    }

    #[test]
    fn error_page_includes_status_and_message_escaped() {
        let html = error_page(404, "not <found>");
        assert!(html.contains("404"));
        assert!(html.contains("not &lt;found&gt;"));
    }
}
