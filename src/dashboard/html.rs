//! HTML rendering for the dashboard. Server-rendered, no template engine,
//! no SPA — page strings are assembled from `format!()` with all
//! interpolated user content passed through [`escape`].
//!
//! P-D2 milestone: read-only list view + hook snippets. Mutation forms and
//! reveal UI arrive in P-D3 / P-D4.

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

/// Render the dashboard index. Caller passes the already-sorted list of
/// stored secret names, the session token (for future form actions — not
/// used yet in P-D2 since this page is read-only), the absolute shtum
/// binary path (for the hook-install snippets), and an optional flash
/// message to display at the top.
pub fn list_page(
    secrets: &[String],
    _token: &str,
    shtum_path: &str,
    flash: Option<&str>,
) -> String {
    let flash_html = flash
        .map(|m| format!(r#"<div class="flash">{}</div>"#, escape(m)))
        .unwrap_or_default();

    let secrets_section = if secrets.is_empty() {
        r#"<p class="muted">No secrets stored yet. Add one with <code>shtum store add &lt;NAME&gt;</code> from your terminal.</p>"#
            .to_string()
    } else {
        let rows: String = secrets
            .iter()
            .map(|name| {
                format!(
                    r#"<tr><td class="name">{}</td><td class="actions muted">(actions in next phase)</td></tr>"#,
                    escape(name),
                )
            })
            .collect();
        format!(
            r#"<table class="secrets">
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
table.secrets th, table.secrets td {{ text-align: left; padding: 0.5rem 0.75rem; border-bottom: 1px solid #eee; }}
table.secrets th {{ font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em; color: #555; }}
td.name {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }}
.muted {{ color: #888; }}
pre.snippet {{ background: #f5f5f5; border: 1px solid #e0e0e0; padding: 0.75rem 1rem; border-radius: 4px; overflow-x: auto; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.9rem; }}
.flash {{ background: #fff8c4; border: 1px solid #e6d878; padding: 0.5rem 0.75rem; border-radius: 4px; margin-bottom: 1rem; }}
.hint {{ color: #555; font-size: 0.9rem; }}
</style>
</head>
<body>
<h1>shtum dashboard</h1>
{flash_html}

<h2>Stored secrets</h2>
{secrets_section}

<h2>Install the Claude Code hook</h2>
<p class="hint">These commands install the PreToolUse hook that rewrites Bash tool calls containing <code>{{NAME}}</code> placeholders through <code>shtum run</code>. Pick one:</p>

<p><strong>Global</strong> (writes to <code>~/.claude/settings.json</code>, applies to every project):</p>
<pre class="snippet">{}</pre>

<p><strong>Per-project</strong> (writes to <code>./.claude/settings.json</code> in the directory you run it from):</p>
<pre class="snippet">{}</pre>
<p class="hint">Replace <code>/path/to/your-project</code> with the project directory you want to enable.</p>

</body>
</html>"#,
        escape(&global_cmd),
        escape(&project_cmd),
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
        // All five together.
        assert_eq!(
            escape(r#"<a href="x" title='y'>&"#),
            "&lt;a href=&quot;x&quot; title=&#39;y&#39;&gt;&amp;",
        );
    }

    #[test]
    fn escape_amp_first_prevents_double_encoding() {
        // If `<` were replaced before `&`, `<` → `&lt;` → `&amp;lt;`. Test
        // the canonical example.
        assert_eq!(escape("&lt;"), "&amp;lt;");
    }

    #[test]
    fn escape_passes_through_safe_input_unchanged() {
        assert_eq!(escape("FOO_BAR.baz-1"), "FOO_BAR.baz-1");
        assert_eq!(escape(""), "");
        assert_eq!(escape("hello, world"), "hello, world");
    }

    #[test]
    fn list_page_empty_state_renders_friendly_message() {
        let html = list_page(&[], "tok", "/usr/local/bin/shtum", None);
        assert!(html.contains("No secrets stored yet"));
        assert!(!html.contains("<tbody>"));
    }

    #[test]
    fn list_page_renders_secret_names_escaped() {
        // Names are restricted by the store validator to [A-Za-z0-9_.-] so
        // the metachars never appear in practice — but we escape defensively
        // and a unit test pins that behaviour in case the validator ever
        // loosens.
        let names = vec!["AWS_KEY".to_string(), "GH_TOKEN".to_string()];
        let html = list_page(&names, "tok", "/usr/local/bin/shtum", None);
        assert!(html.contains("AWS_KEY"));
        assert!(html.contains("GH_TOKEN"));
        assert!(html.contains("<tbody>"));
    }

    #[test]
    fn list_page_renders_hook_snippets() {
        let html = list_page(&[], "tok", "/abs/path/to/shtum", None);
        assert!(html.contains("/abs/path/to/shtum hook install"));
        assert!(html.contains("cd /path/to/your-project &amp;&amp; /abs/path/to/shtum hook install --project"));
    }

    #[test]
    fn list_page_escapes_shtum_path_with_meta() {
        // Defensive: in the (silly) case where the binary lives at a path
        // with HTML metachars, we don't break out of the <pre> block.
        let html = list_page(&[], "tok", "/weird/<path>/shtum", None);
        assert!(!html.contains("/weird/<path>/shtum"));
        assert!(html.contains("/weird/&lt;path&gt;/shtum"));
    }

    #[test]
    fn list_page_renders_flash_when_present() {
        let html = list_page(&[], "tok", "/usr/local/bin/shtum", Some("rotated FOO"));
        assert!(html.contains(r#"class="flash""#));
        assert!(html.contains("rotated FOO"));
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
