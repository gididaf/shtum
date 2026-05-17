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

/// Minimal projection of a temp-key registry entry, just the bits the
/// dashboard needs to render the row. Mod.rs owns the
/// registry-snapshot → view conversion so html.rs has zero registry-
/// type dependencies.
pub struct TempEntryView {
    pub name: String,
    pub expires_at: u64,
}

/// Single dark-theme stylesheet, kept in one place so the page template
/// stays readable. Linked as inline `<style>` (CSP allows `style-src
/// 'unsafe-inline'`).
const STYLES: &str = r#"
:root {
  --bg:#0b0f17;
  --surface:#11161f;
  --surface-2:#161c27;
  --surface-3:#0d1219;
  --border:#1f2733;
  --border-strong:#2a3340;
  --text:#e7eaef;
  --text-muted:#9aa3b2;
  --accent:#3b82f6;
  --accent-hover:#2563eb;
  --accent-fg:#fff;
  --danger:#ef4444;
  --danger-fg:#fecaca;
  --danger-border:#5a2229;
  --danger-bg:#2a141a;
  --reveal-bg:#1a2410;
  --reveal-border:#3a4f24;
  --reveal-fg:#d8eab9;
  --shadow:0 1px 0 rgba(255,255,255,0.02), 0 8px 24px rgba(0,0,0,0.4);
  --radius:8px;
  --radius-sm:6px;
}

* { box-sizing: border-box; }
html, body { background: var(--bg); color: var(--text); }
body {
  font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  margin: 0;
  -webkit-font-smoothing: antialiased;
}
code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
a { color: var(--accent); }

.topbar {
  border-bottom: 1px solid var(--border);
  background: linear-gradient(180deg, #0e131c 0%, #0b0f17 100%);
}
.topbar__inner { max-width: 980px; margin: 0 auto; padding: 1.1rem 1.25rem; display: flex; align-items: baseline; gap: 0.75rem; }
.brand { font-size: 1.05rem; font-weight: 600; letter-spacing: 0.02em; color: var(--text); }
.brand__sub { color: var(--text-muted); font-size: 0.85rem; }

.tabnav {
  background: var(--surface-3);
  border-bottom: 1px solid var(--border);
}
.tabnav__inner {
  max-width: 980px;
  margin: 0 auto;
  padding: 0 1.25rem;
  display: flex;
  gap: 0.25rem;
}
.tab {
  appearance: none;
  background: transparent;
  border: 0;
  color: var(--text-muted);
  font: inherit;
  font-size: 0.88rem;
  font-weight: 500;
  padding: 0.85rem 1rem;
  cursor: pointer;
  border-bottom: 2px solid transparent;
  margin-bottom: -1px;
  transition: color 120ms ease, border-color 120ms ease;
}
.tab:hover { color: var(--text); }
.tab[aria-selected="true"] {
  color: var(--text);
  border-bottom-color: var(--accent);
}
.tab:focus-visible { outline: 2px solid var(--accent); outline-offset: -2px; }

.page { max-width: 980px; margin: 0 auto; padding: 1.5rem 1.25rem 4rem; }

.section { margin-top: 2rem; }
.section:first-of-type { margin-top: 0.5rem; }
.section__head { margin-bottom: 0.75rem; }
.section__head h2 { margin: 0 0 0.25rem; font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.1em; color: var(--text-muted); font-weight: 600; }
.section__sub { margin: 0; color: var(--text-muted); font-size: 0.9rem; }
.section__sub code { background: var(--surface-2); padding: 0.05rem 0.35rem; border-radius: 3px; font-size: 0.85rem; color: var(--text); }

.card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 1rem 1.1rem;
  margin-bottom: 0.75rem;
  box-shadow: var(--shadow);
}

.add-card .form-row { display: flex; gap: 0.75rem; align-items: end; flex-wrap: wrap; }
.field { display: flex; flex-direction: column; gap: 0.3rem; }
.field--grow { flex: 1 1 240px; }
.field--actions { justify-content: end; }
.field label { font-size: 0.72rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.07em; font-weight: 600; }

input[type=text], input[type=password] {
  background: #0b0f17;
  color: var(--text);
  border: 1px solid var(--border-strong);
  border-radius: var(--radius-sm);
  padding: 0.5rem 0.65rem;
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 0.88rem;
  min-width: 0;
}
input[type=text]:focus, input[type=password]:focus {
  outline: 2px solid var(--accent);
  outline-offset: 0;
  border-color: transparent;
}
input::placeholder { color: #4b5563; }
.input--grow { flex: 1 1 200px; }

.btn {
  display: inline-flex; align-items: center; justify-content: center; gap: 0.35rem;
  padding: 0.45rem 0.85rem;
  border-radius: var(--radius-sm);
  font: inherit; font-size: 0.85rem; font-weight: 500;
  cursor: pointer;
  transition: background 120ms ease, border-color 120ms ease, color 120ms ease;
  border: 1px solid var(--border-strong);
  background: var(--surface-2);
  color: var(--text);
  white-space: nowrap;
}
.btn:hover { background: #1d2532; border-color: #344052; }
.btn:focus-visible { outline: 2px solid var(--accent); outline-offset: 1px; }
.btn--primary { background: var(--accent); border-color: var(--accent); color: var(--accent-fg); }
.btn--primary:hover { background: var(--accent-hover); border-color: var(--accent-hover); }
.btn--ghost { background: transparent; }
.btn--ghost:hover { background: var(--surface-2); }
.btn--danger { background: transparent; border-color: var(--danger-border); color: var(--danger-fg); }
.btn--danger:hover { background: var(--danger-bg); border-color: var(--danger); }
.btn--copy { font-size: 0.75rem; padding: 0.25rem 0.65rem; }
.btn--toggle .caret { transition: transform 120ms ease; display: inline-block; }
.btn--toggle[aria-expanded="true"] .caret { transform: rotate(180deg); }

.flash { margin: 0 0 1rem; padding: 0.65rem 0.85rem; border-radius: var(--radius-sm); border: 1px solid #1d3a5e; background: #142233; color: #cfe1ff; }
.flash.error { background: var(--danger-bg); border-color: var(--danger-border); color: var(--danger-fg); }

.empty { padding: 1.2rem 1.1rem; border: 1px dashed var(--border-strong); border-radius: var(--radius); color: var(--text-muted); background: var(--surface); }
.empty p { margin: 0 0 0.4rem; }
.empty p:last-child { margin: 0; }

.secret-list {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  overflow: hidden;
  box-shadow: var(--shadow);
}
.secret-list__head {
  display: grid;
  grid-template-columns: 1fr auto;
  gap: 1rem;
  padding: 0.55rem 1rem;
  background: #0e131c;
  color: var(--text-muted);
  font-size: 0.7rem;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  font-weight: 600;
  border-bottom: 1px solid var(--border);
}
.secret-row + .secret-row { border-top: 1px solid var(--border); }
.secret-row__main {
  display: grid;
  grid-template-columns: 1fr auto;
  gap: 1rem;
  padding: 0.75rem 1rem;
  align-items: center;
}
.secret-name { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; color: var(--text); font-size: 0.92rem; }
.secret-row__actions { display: flex; gap: 0.4rem; align-items: center; flex-wrap: wrap; }

.value-display {
  display: none;
  padding: 0.25rem 0.55rem;
  background: var(--reveal-bg);
  border: 1px solid var(--reveal-border);
  border-radius: 3px;
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 0.8rem;
  color: var(--reveal-fg);
  word-break: break-all;
  max-width: 320px;
}
.value-display.shown { display: inline-block; }

.secret-edit { padding: 0 1rem; background: var(--surface-3); border-top: 1px solid var(--border); }
.secret-edit[hidden] { display: none; }
.edit-section { padding: 0.85rem 0; }
.edit-section + .edit-section { border-top: 1px solid var(--border); }
.edit-section h4 { margin: 0 0 0.5rem; font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.08em; color: var(--text-muted); font-weight: 600; }
.edit-section .form-row { display: flex; gap: 0.5rem; align-items: center; flex-wrap: wrap; }
.edit-section--danger h4 { color: var(--danger-fg); }

.check { display: inline-flex; align-items: center; gap: 0.4rem; color: var(--text-muted); font-size: 0.82rem; cursor: pointer; user-select: none; }
.check input { accent-color: var(--accent); }

.snippet-card { padding: 0; }
.snippet-card__head { display: flex; gap: 0.6rem; align-items: baseline; padding: 0.85rem 1rem 0.4rem; flex-wrap: wrap; }
.snippet-card__head h3 { margin: 0; font-size: 0.95rem; }
.snippet-card__head .muted { color: var(--text-muted); font-size: 0.85rem; }
.snippet { position: relative; padding: 0 1rem 1rem; }
.snippet pre { background: #060a10; border: 1px solid var(--border); padding: 0.7rem 0.9rem; padding-right: 4.5rem; border-radius: var(--radius-sm); margin: 0; overflow-x: auto; font-size: 0.82rem; color: #d3d9e1; line-height: 1.5; }
.snippet .btn--copy {
  position: absolute;
  top: 0.45rem;
  right: 1.4rem;
  background: var(--surface-2);
  border-color: var(--border-strong);
  z-index: 1;
}
.snippet .btn--copy:hover { background: #1d2532; }
.snippet-card .hint { margin: -0.4rem 1rem 1rem; color: var(--text-muted); font-size: 0.85rem; }

.docs-subhead {
  margin: 1rem 0 0.5rem;
  font-size: 0.72rem;
  text-transform: uppercase;
  letter-spacing: 0.07em;
  color: var(--text-muted);
  font-weight: 600;
}
.docs-subhead:first-child { margin-top: 0; }
.ref-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.85rem;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  overflow: hidden;
  box-shadow: var(--shadow);
}
.ref-table thead th {
  background: #0e131c;
  color: var(--text-muted);
  font-size: 0.7rem;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  font-weight: 600;
  text-align: left;
  padding: 0.55rem 0.85rem;
  border-bottom: 1px solid var(--border);
}
.ref-table td {
  padding: 0.55rem 0.85rem;
  text-align: left;
  border-bottom: 1px solid var(--border);
  vertical-align: top;
  color: var(--text);
}
.ref-table tr:last-child td { border-bottom: 0; }
.ref-table td:first-child { white-space: nowrap; width: 1%; }
.ref-table td code, .ref-note code {
  background: var(--surface-2);
  padding: 0.05rem 0.35rem;
  border-radius: 3px;
  font-size: 0.85rem;
  color: var(--text);
}
.ref-note { color: var(--text-muted); font-size: 0.82rem; margin: 0.6rem 0 0; }

.muted { color: var(--text-muted); }

.badge {
  display: inline-flex;
  align-items: center;
  gap: 0.3rem;
  padding: 0.15rem 0.55rem;
  border-radius: 999px;
  font-size: 0.7rem;
  font-weight: 600;
  letter-spacing: 0.05em;
  text-transform: uppercase;
  white-space: nowrap;
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
}
.badge--temp {
  background: #2a2014;
  border: 1px solid #5a4324;
  color: #f3cf86;
}
.badge--temp.is-expired {
  background: var(--danger-bg);
  border-color: var(--danger-border);
  color: var(--danger-fg);
}
.badge__label { opacity: 0.75; }
.badge__time { font-variant-numeric: tabular-nums; }

.extend-form { margin: 0; display: inline-block; }
.extend-form button { padding: 0.3rem 0.6rem; font-size: 0.78rem; }
"#;

/// Inline JS: reveal/hide, copy, edit-panel toggle, and a generic
/// confirm-on-collision submit hook used by both the Add form and the
/// per-row Rename form. Collision check uses the secret names embedded
/// as JSON in `<body data-secret-names="[...]">` — values are never
/// embedded, only names (which are public on the page anyway). The form
/// declares which input holds the candidate name via `data-name-input`,
/// and an optional `data-current-name` lets Rename skip a same-name
/// no-op without prompting. CSP allows `script-src 'unsafe-inline'`.
const SCRIPT: &str = r#"
(function() {
  var token = document.body.dataset.token;
  var knownNames = new Set();
  try { knownNames = new Set(JSON.parse(document.body.dataset.secretNames || '[]')); } catch (_) {}

  document.addEventListener('click', function(e) {
    var btn = e.target.closest('[data-action]');
    if (!btn) return;
    var action = btn.dataset.action;
    if (action === 'reveal') return revealOrHide(btn);
    if (action === 'copy') return copySnippet(btn);
    if (action === 'toggle-edit') return togglePanel(btn);
  });

  document.addEventListener('submit', function(e) {
    var form = e.target.closest('form[data-confirm-overwrite]');
    if (!form) return;
    var inputName = form.dataset.nameInput;
    if (!inputName) return;
    var input = form.querySelector('input[name="' + inputName + '"]');
    if (!input) return;
    var typed = input.value.trim();
    if (!typed) return;
    var current = form.dataset.currentName;
    if (current && typed === current) return; // server handles no-op
    if (!knownNames.has(typed)) return; // no collision, normal submit
    var ok = confirm('A secret named "' + typed + '" already exists.\n\nOverwrite it? This will destroy the existing value stored under that name.');
    if (!ok) { e.preventDefault(); return; }
    // User confirmed — add a hidden force=on field so the server overwrites.
    var force = document.createElement('input');
    force.type = 'hidden';
    force.name = 'force';
    force.value = 'on';
    form.appendChild(force);
  });

  function revealOrHide(btn) {
    var cell = btn.parentElement.querySelector('.value-display');
    if (!cell) return;
    if (btn.dataset.shown === '1') { hide(btn, cell); return; }
    var name = btn.dataset.name;
    fetch('/secrets/' + encodeURIComponent(name) + '/reveal?token=' + encodeURIComponent(token))
      .then(function(r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.text(); })
      .then(function(value) {
        cell.textContent = value;
        cell.classList.add('shown');
        btn.textContent = 'Hide';
        btn.dataset.shown = '1';
        if (btn._t) clearTimeout(btn._t);
        btn._t = setTimeout(function() { hide(btn, cell); }, 30000);
      })
      .catch(function(err) { alert('reveal failed: ' + err.message); });
  }
  function hide(btn, cell) {
    cell.textContent = '';
    cell.classList.remove('shown');
    btn.textContent = 'Reveal';
    btn.dataset.shown = '';
    if (btn._t) { clearTimeout(btn._t); btn._t = null; }
  }
  function copySnippet(btn) {
    var target = document.getElementById(btn.dataset.target);
    if (!target) return;
    var text = target.textContent;
    if (!navigator.clipboard) { alert('clipboard API unavailable'); return; }
    navigator.clipboard.writeText(text).then(function() {
      var orig = btn.dataset.orig || btn.textContent;
      btn.dataset.orig = orig;
      btn.textContent = 'Copied!';
      setTimeout(function() { btn.textContent = orig; }, 1500);
    }).catch(function(err) { alert('copy failed: ' + err.message); });
  }
  function togglePanel(btn) {
    var name = btn.dataset.name;
    var panel = document.getElementById('edit-' + name);
    if (!panel) return;
    var open = panel.hidden === false;
    if (open) {
      panel.hidden = true;
      btn.setAttribute('aria-expanded', 'false');
    } else {
      panel.hidden = false;
      btn.setAttribute('aria-expanded', 'true');
    }
  }
})();

(function() {
  // Per-row TEMP badge countdown. Server renders the absolute expiry
  // epoch in `data-expires-at`; this ticker formats the remaining time
  // client-side so a long-open tab stays accurate without re-fetch.
  function fmt(s) {
    if (s <= 0) return 'expired';
    if (s >= 86400) return Math.floor(s/86400) + 'd ' + Math.floor((s%86400)/3600) + 'h';
    if (s >= 3600) return Math.floor(s/3600) + 'h ' + Math.floor((s%3600)/60) + 'm';
    if (s >= 60) return Math.floor(s/60) + 'm ' + (s%60) + 's';
    return s + 's';
  }
  function tick() {
    var nodes = document.querySelectorAll('[data-expires-at]');
    if (!nodes.length) return;
    var now = Math.floor(Date.now() / 1000);
    nodes.forEach(function(b) {
      var exp = parseInt(b.dataset.expiresAt, 10);
      if (isNaN(exp)) return;
      var rem = exp - now;
      var t = b.querySelector('.badge__time');
      if (t) t.textContent = fmt(rem);
      if (rem <= 0) {
        b.classList.add('is-expired');
      } else {
        b.classList.remove('is-expired');
      }
    });
  }
  tick();
  if (document.querySelector('[data-expires-at]')) setInterval(tick, 1000);
})();

(function() {
  var tabs = Array.prototype.slice.call(document.querySelectorAll('[role="tab"]'));
  if (!tabs.length) return;
  function activate(target, focus) {
    tabs.forEach(function(t) {
      var selected = t === target;
      t.setAttribute('aria-selected', selected ? 'true' : 'false');
      t.tabIndex = selected ? 0 : -1;
      var panel = document.getElementById(t.getAttribute('aria-controls'));
      if (panel) panel.hidden = !selected;
    });
    if (focus) target.focus();
  }
  var hash = location.hash.replace(/^#/, '');
  var initial = null;
  for (var i = 0; i < tabs.length; i++) {
    if (tabs[i].dataset.tabKey === hash) { initial = tabs[i]; break; }
  }
  activate(initial || tabs[0], false);
  tabs.forEach(function(t) {
    t.addEventListener('click', function() {
      activate(t, false);
      var key = t.dataset.tabKey;
      var newHash = key === tabs[0].dataset.tabKey ? '' : '#' + key;
      history.replaceState(null, '', location.pathname + location.search + newHash);
    });
    t.addEventListener('keydown', function(e) {
      var idx = tabs.indexOf(t);
      if (e.key === 'ArrowRight' || e.key === 'ArrowDown') {
        e.preventDefault();
        activate(tabs[(idx + 1) % tabs.length], true);
      } else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') {
        e.preventDefault();
        activate(tabs[(idx - 1 + tabs.length) % tabs.length], true);
      } else if (e.key === 'Home') {
        e.preventDefault();
        activate(tabs[0], true);
      } else if (e.key === 'End') {
        e.preventDefault();
        activate(tabs[tabs.length - 1], true);
      }
    });
  });
})();
"#;

/// Render the dashboard index. The session token is embedded in every
/// form as a hidden field so each POST can be verified server-side
/// without relying on cookies. Names in `temp_entries` are rendered
/// with a per-row TEMP badge + Extend button; their `expires_at`
/// drives the client-side countdown.
pub fn list_page(
    secrets: &[String],
    temp_entries: &[TempEntryView],
    token: &str,
    shtum_path: &str,
    flash: Option<Flash<'_>>,
) -> String {
    let token_esc = escape(token);

    // O(1) lookup from name → expires_at for the row renderer. Names
    // already pass `validate_name` so no fancy hashing or normalisation
    // is needed.
    let temp_lookup: std::collections::HashMap<&str, u64> = temp_entries
        .iter()
        .map(|t| (t.name.as_str(), t.expires_at))
        .collect();

    let flash_html = flash
        .map(|f| {
            let class = match f.kind {
                FlashKind::Info => "flash",
                FlashKind::Error => "flash error",
            };
            format!(r#"<div class="{}">{}</div>"#, class, escape(f.message))
        })
        .unwrap_or_default();

    let quick_form = format!(
        r#"<div class="card add-card">
<form class="form-row" action="/secrets/quick" method="post" autocomplete="off">
<input type="hidden" name="token" value="{token}">
<div class="field field--grow"><label for="quick-value">Value</label><input id="quick-value" type="password" name="value" placeholder="(hidden) — stash and get an auto-name back" required></div>
<div class="field"><label for="quick-ttl">Idle TTL</label><input id="quick-ttl" type="text" name="ttl" placeholder="4h" pattern="[0-9]+[smhd]"></div>
<div class="field field--actions"><button type="submit" class="btn btn--primary">Quick stash</button></div>
</form>
</div>"#,
        token = token_esc,
    );

    let add_form = format!(
        r#"<div class="card add-card">
<form class="form-row" action="/secrets/add" method="post" autocomplete="off" data-confirm-overwrite data-name-input="name">
<input type="hidden" name="token" value="{token}">
<div class="field"><label for="add-name">Name</label><input id="add-name" type="text" name="name" placeholder="MY_SECRET" required pattern="[A-Za-z0-9_.\-]+"></div>
<div class="field field--grow"><label for="add-value">Value</label><input id="add-value" type="password" name="value" placeholder="(hidden)" required></div>
<div class="field field--actions"><button type="submit" class="btn btn--primary">Add secret</button></div>
</form>
</div>"#,
        token = token_esc,
    );

    let secrets_list = if secrets.is_empty() {
        r#"<div class="empty"><p>No secrets stored yet.</p><p class="muted">Add one above, or via <code>shtum store add &lt;NAME&gt;</code> from your terminal.</p></div>"#.to_string()
    } else {
        let rows: String = secrets
            .iter()
            .map(|name| render_secret_row(name, &token_esc, temp_lookup.get(name.as_str()).copied()))
            .collect();
        format!(
            r#"<div class="secret-list">
<div class="secret-list__head"><span>Name</span><span>Actions</span></div>
{rows}
</div>"#,
        )
    };

    let global_cmd = format!("{} hook install", shtum_path);
    let project_cmd = format!(
        "cd /path/to/your-project && {} hook install --project",
        shtum_path,
    );

    // Names go through `validate_name` before storage, so they're always
    // safe ASCII (no quotes, backslashes, control chars). That makes
    // building the JSON manually trivial — no need for serde_json.
    let names_json = {
        let mut s = String::from("[");
        for (i, n) in secrets.iter().enumerate() {
            if i > 0 { s.push(','); }
            s.push('"');
            s.push_str(n);
            s.push('"');
        }
        s.push(']');
        s
    };
    let names_json_attr = escape(&names_json);

    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>shtum dashboard</title>
<style>{styles}</style>
</head>
<body data-token="{token}" data-secret-names="{names_json_attr}">
<header class="topbar"><div class="topbar__inner"><span class="brand">shtum</span><span class="brand__sub">local secrets dashboard</span></div></header>
<nav class="tabnav"><div class="tabnav__inner" role="tablist" aria-label="Sections">
<button type="button" class="tab" role="tab" id="tab-keys" data-tab-key="keys" aria-controls="panel-keys" aria-selected="true" tabindex="0">Keys</button>
<button type="button" class="tab" role="tab" id="tab-docs" data-tab-key="docs" aria-controls="panel-docs" aria-selected="false" tabindex="-1">Docs</button>
</div></nav>
<main class="page">
{flash_html}

<section id="panel-keys" role="tabpanel" aria-labelledby="tab-keys">

<section class="section">
<header class="section__head"><h2>Quick stash</h2><p class="section__sub">Paste a one-off value — get back an auto-generated <code>TMP_XXXXXX</code> name. Auto-removes after the idle window with no <code>shtum run</code> reference and no Extend press. Default 4h.</p></header>
{quick_form}
</section>

<section class="section">
<header class="section__head"><h2>Add a secret</h2><p class="section__sub">Names live in the macOS Keychain. Values are never logged.</p></header>
{add_form}
</section>

<section class="section">
<header class="section__head"><h2>Stored secrets</h2></header>
{secrets_list}
</section>

</section>

<section id="panel-docs" role="tabpanel" aria-labelledby="tab-docs" hidden>

<section class="section">
<header class="section__head"><h2>Install the Claude Code hook</h2><p class="section__sub">These commands install the PreToolUse hook that rewrites Bash tool calls containing <code>{{NAME}}</code> placeholders through <code>shtum run</code>. Pick one:</p></header>

<div class="card snippet-card">
<div class="snippet-card__head"><h3>Global</h3><span class="muted">writes to <code>~/.claude/settings.json</code>, applies to every project</span></div>
<div class="snippet"><pre id="snippet-global">{global_cmd}</pre><button type="button" class="btn btn--ghost btn--copy" data-action="copy" data-target="snippet-global">Copy</button></div>
</div>

<div class="card snippet-card">
<div class="snippet-card__head"><h3>Per-project</h3><span class="muted">writes to <code>./.claude/settings.json</code> in the directory you run it from</span></div>
<div class="snippet"><pre id="snippet-project">{project_cmd}</pre><button type="button" class="btn btn--ghost btn--copy" data-action="copy" data-target="snippet-project">Copy</button></div>
<p class="hint">Replace <code>/path/to/your-project</code> with the project directory you want to enable.</p>
</div>
</section>

<section class="section">
<header class="section__head"><h2>Placeholder reference</h2><p class="section__sub">Two orthogonal axes: the <strong>source</strong> prefix says where the value comes from, the <strong>mode</strong> prefix says how it reaches the subprocess. Bare <code>{{NAME}}</code> means default source (Keychain, env fallback) + default mode (literal argv substitution).</p></header>

<h3 class="docs-subhead">Source prefixes</h3>
<table class="ref-table">
<thead><tr><th>Form</th><th>Where the value comes from</th></tr></thead>
<tbody>
<tr><td><code>{{NAME}}</code></td><td>Keychain, falling back to the environment variable <code>NAME</code>.</td></tr>
<tr><td><code>{{kc:NAME}}</code></td><td>Keychain only. Errors if missing — never falls back to env.</td></tr>
<tr><td><code>{{env:NAME}}</code></td><td>Environment variable only. Ignores the Keychain even if a matching entry exists.</td></tr>
<tr><td><code>{{file:PATH}}</code></td><td>File contents at <code>PATH</code> (one trailing newline trimmed).</td></tr>
</tbody>
</table>

<h3 class="docs-subhead">Mode prefixes</h3>
<table class="ref-table">
<thead><tr><th>Form</th><th>How the value reaches the subprocess</th></tr></thead>
<tbody>
<tr><td><code>{{argv:NAME}}</code></td><td>Explicit literal argv substitution. Prints a stderr warning that the value is visible in <code>ps</code> while the subprocess runs.</td></tr>
<tr><td><code>{{env-inject:NAME}}</code></td><td>Directive: must be a standalone argv slot. The slot is stripped, and <code>NAME=&lt;value&gt;</code> is set in the subprocess environment.</td></tr>
<tr><td><code>{{stdin:NAME}}</code></td><td>Directive: must be a standalone argv slot. The slot is stripped, and the value is piped to the subprocess on stdin. Max one per command.</td></tr>
<tr><td><code>{{tempfile:NAME}}</code></td><td>Inline: replaced with the path to a <code>0600</code> temp file holding the value. Multiple refs to the same name share one file. RAII cleanup on normal exit.</td></tr>
</tbody>
</table>

<p class="ref-note">In v1, mode prefixes always pair with the default source (Keychain + env fallback). They don't combine with <code>kc:</code> / <code>env:</code> / <code>file:</code>.</p>
</section>

<section class="section">
<header class="section__head"><h2>Worked examples</h2><p class="section__sub">Paste-ready commands for common patterns.</p></header>

<div class="card snippet-card">
<div class="snippet-card__head"><h3>HTTP request with a Bearer token</h3><span class="muted">value pulled from Keychain at exec time, scrubbed from output</span></div>
<div class="snippet"><pre id="snippet-example-curl">shtum run -- curl -H "Authorization: Bearer {{CF_TOKEN}}" https://api.cloudflare.com/client/v4/user</pre><button type="button" class="btn btn--ghost btn--copy" data-action="copy" data-target="snippet-example-curl">Copy</button></div>
</div>

<div class="card snippet-card">
<div class="snippet-card__head"><h3>kubectl with a token from a file</h3><span class="muted"><code>{{file:PATH}}</code> reads file contents at exec time</span></div>
<div class="snippet"><pre id="snippet-example-kubectl">shtum run -- kubectl --token={{file:/run/secrets/k8s-token}} get pods</pre><button type="button" class="btn btn--ghost btn--copy" data-action="copy" data-target="snippet-example-kubectl">Copy</button></div>
</div>
</section>

<section class="section">
<header class="section__head"><h2>Runtime flags</h2><p class="section__sub">Flags for <code>shtum run</code>. Defaults are safe; toggle when you need different behaviour.</p></header>

<table class="ref-table">
<thead><tr><th>Flag</th><th>Effect</th></tr></thead>
<tbody>
<tr><td><code>--dry-run</code></td><td>Resolve all placeholders and print the rewritten invocation with values masked as <code>[REDACTED:&lt;placeholder&gt;]</code>. Nothing is executed. Doubles as a "are my secrets reachable?" check.</td></tr>
<tr><td><code>--no-auto-redact</code></td><td>Disable the automatic scrubber that replaces literal / URL-encoded / base64 occurrences of injected secret values in stdout / stderr. Debugging only.</td></tr>
<tr><td><code>--redact &lt;REGEX&gt;</code></td><td>Additional regex pattern to redact from subprocess output. Repeatable. Merged with the built-in default set (unless <code>--no-default-redact</code> is also passed).</td></tr>
<tr><td><code>--no-default-redact</code></td><td>Disable the built-in default regex set (JWTs, AWS access keys, Bearer tokens, GitHub PATs). Any <code>--redact</code> patterns are still applied.</td></tr>
</tbody>
</table>
</section>

</section>
</main>

<script>{script}</script>
</body>
</html>"#,
        styles = STYLES,
        script = SCRIPT,
        token = token_esc,
        global_cmd = escape(&global_cmd),
        project_cmd = escape(&project_cmd),
    )
}

/// Render a single secret row: a tight always-visible header (name +
/// Reveal + Edit toggle) plus an `aria-expanded`-controlled panel
/// containing the Rename / Rotate / Delete forms (name comes first —
/// identity before content). The panel is `hidden` by default; the
/// inline JS toggles it. The rename form is marked with
/// `data-rename-form` so the page-level JS can intercept submit and
/// `confirm()` on a collision with an existing name (adding `force=on`
/// if the user agrees to overwrite). The delete form keeps an
/// `onsubmit` confirm() so a misclicked Delete still asks for
/// confirmation even if the page-level JS errored out.
fn render_secret_row(name: &str, token_esc: &str, temp_expires_at: Option<u64>) -> String {
    let name_esc = escape(name);
    let confirm_msg = escape(&format!(
        "Delete \"{name}\" from the Keychain? This cannot be undone.",
    ));
    let panel_id = format!("edit-{name_esc}");
    // TEMP badge + Extend button only when the registry tracks this name.
    // The countdown JS reads `data-expires-at` and ticks the inner
    // `.badge__time` text once per second.
    let temp_surface = match temp_expires_at {
        Some(exp) => format!(
            r#"<span class="badge badge--temp" data-expires-at="{exp}"><span class="badge__label">TEMP</span><span class="badge__time">…</span></span>
<form class="extend-form" action="/secrets/{name_esc}/extend" method="post"><input type="hidden" name="token" value="{token_esc}"><button type="submit" class="btn btn--ghost">Extend</button></form>
"#,
        ),
        None => String::new(),
    };
    format!(
        r#"<div class="secret-row">
<div class="secret-row__main">
<div class="secret-name">{name_esc}</div>
<div class="secret-row__actions">
{temp_surface}<button type="button" class="btn btn--ghost" data-action="reveal" data-name="{name_esc}">Reveal</button>
<span class="value-display"></span>
<button type="button" class="btn btn--ghost btn--toggle" data-action="toggle-edit" data-name="{name_esc}" aria-expanded="false" aria-controls="{panel_id}">Edit <span class="caret">&#9662;</span></button>
</div>
</div>
<div class="secret-edit" id="{panel_id}" hidden>

<div class="edit-section">
<h4>Rename</h4>
<form class="form-row" action="/secrets/{name_esc}/rename" method="post" autocomplete="off" data-confirm-overwrite data-name-input="new_name" data-current-name="{name_esc}">
<input type="hidden" name="token" value="{token_esc}">
<input type="hidden" name="name" value="{name_esc}">
<input type="text" name="new_name" placeholder="new name" required pattern="[A-Za-z0-9_.\-]+" class="input--grow">
<button type="submit" class="btn btn--primary">Rename</button>
</form>
</div>

<div class="edit-section">
<h4>Rotate value</h4>
<form class="form-row" action="/secrets/{name_esc}/rotate" method="post" autocomplete="off">
<input type="hidden" name="token" value="{token_esc}">
<input type="hidden" name="name" value="{name_esc}">
<input type="password" name="value" placeholder="new value" required class="input--grow">
<button type="submit" class="btn btn--primary">Rotate</button>
</form>
</div>

<div class="edit-section edit-section--danger">
<h4>Danger zone</h4>
<form class="form-row" action="/secrets/{name_esc}/delete" method="post" onsubmit="return confirm('{confirm_msg}');">
<input type="hidden" name="token" value="{token_esc}">
<input type="hidden" name="name" value="{name_esc}">
<button type="submit" class="btn btn--danger">Delete {name_esc}</button>
</form>
</div>

</div>
</div>"#,
    )
}

/// Minimal error page for non-200 responses. Same dark palette as the
/// main page so a mistyped URL doesn't flash a white background.
pub fn error_page(status: u16, msg: &str) -> String {
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{status} — shtum dashboard</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: #0b0f17; color: #e7eaef; max-width: 600px; margin: 4rem auto; padding: 2rem; }}
h1 {{ margin: 0 0 0.5rem; font-size: 2rem; color: #9aa3b2; }}
p {{ margin: 0; color: #e7eaef; }}
</style>
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
        let html = list_page(&[], &[], "tok", "/usr/local/bin/shtum", None);
        assert!(html.contains("No secrets stored yet"));
        assert!(!html.contains(r#"class="secret-list""#));
        assert!(html.contains(r#"action="/secrets/add""#));
    }

    #[test]
    fn list_page_renders_per_row_rotate_rename_and_delete_forms() {
        let names = vec!["AWS_KEY".to_string(), "GH_TOKEN".to_string()];
        let html = list_page(&names, &[], "tok", "/usr/local/bin/shtum", None);
        assert!(html.contains(r#"action="/secrets/AWS_KEY/rotate""#));
        assert!(html.contains(r#"action="/secrets/AWS_KEY/rename""#));
        assert!(html.contains(r#"action="/secrets/AWS_KEY/delete""#));
        assert!(html.contains(r#"action="/secrets/GH_TOKEN/rotate""#));
        assert!(html.contains(r#"action="/secrets/GH_TOKEN/rename""#));
        assert!(html.contains(r#"action="/secrets/GH_TOKEN/delete""#));
    }

    #[test]
    fn list_page_rename_form_uses_data_attrs_for_collision_confirm() {
        // The dashboard no longer renders a Force checkbox — instead the
        // page-level JS intercepts submit, checks the typed name against
        // the names embedded in `<body data-secret-names>`, and
        // `confirm()`s before adding `force=on` as a hidden field. The
        // form must therefore (a) carry `data-confirm-overwrite`, (b)
        // declare which input holds the candidate name, and (c) declare
        // its current name so the JS knows when to skip a same-name no-op.
        let names = vec!["FOO".to_string()];
        let html = list_page(&names, &[], "tok", "/usr/local/bin/shtum", None);
        assert!(html.contains(r#"action="/secrets/FOO/rename""#));
        assert!(html.contains(r#"name="new_name""#));
        assert!(html.contains(r#"data-confirm-overwrite"#));
        assert!(html.contains(r#"data-name-input="new_name""#));
        assert!(html.contains(r#"data-current-name="FOO""#));
        // No standing `force` input in the form — it's added on confirm.
        assert!(!html.contains(r#"name="force""#));
        // No Force checkbox anywhere on the page.
        assert!(!html.contains(r#"type="checkbox""#));
    }

    #[test]
    fn list_page_add_form_uses_data_attrs_for_collision_confirm() {
        // Same generic confirm-on-collision wiring as Rename, but with
        // `name` as the candidate input and no `data-current-name`
        // (Add has no current name to compare against).
        let html = list_page(&[], &[], "tok", "/usr/local/bin/shtum", None);
        // Find the add form and assert its attrs without false-positives
        // from any other form on the page.
        let add_form_idx = html
            .find(r#"action="/secrets/add""#)
            .expect("add form must be present");
        let add_open = html[..add_form_idx]
            .rfind("<form")
            .expect("add form must have an opening tag");
        let add_close = add_form_idx
            + html[add_form_idx..]
                .find('>')
                .expect("add form must close its opening tag");
        let opening = &html[add_open..=add_close];
        assert!(opening.contains("data-confirm-overwrite"), "opening tag: {opening}");
        assert!(opening.contains(r#"data-name-input="name""#), "opening tag: {opening}");
        assert!(!opening.contains("data-current-name"), "opening tag: {opening}");
    }

    #[test]
    fn list_page_embeds_secret_names_for_collision_check() {
        let names = vec!["AWS_KEY".to_string(), "GH_TOKEN".to_string()];
        let html = list_page(&names, &[], "tok", "/usr/local/bin/shtum", None);
        // The body carries the names as a JSON array in a data attribute
        // (HTML-escaped: `"` becomes `&quot;`). The JS reads + parses it.
        assert!(html.contains(r#"data-secret-names="[&quot;AWS_KEY&quot;,&quot;GH_TOKEN&quot;]""#));
    }

    #[test]
    fn list_page_embeds_empty_names_array_when_no_secrets() {
        let html = list_page(&[], &[], "tok", "/usr/local/bin/shtum", None);
        assert!(html.contains(r#"data-secret-names="[]""#));
    }

    #[test]
    fn list_page_renders_rename_section_before_rotate_section() {
        // Identity (the name) before content (the value) — the Rename
        // section's <h4> must appear earlier in the document than the
        // Rotate section's <h4>.
        let names = vec!["FOO".to_string()];
        let html = list_page(&names, &[], "tok", "/usr/local/bin/shtum", None);
        let rename_idx = html.find("<h4>Rename</h4>").expect("rename section present");
        let rotate_idx = html.find("<h4>Rotate value</h4>").expect("rotate section present");
        assert!(
            rename_idx < rotate_idx,
            "Rename section ({rename_idx}) should appear before Rotate ({rotate_idx})"
        );
    }

    #[test]
    fn list_page_edit_panel_is_hidden_by_default() {
        let names = vec!["FOO".to_string()];
        let html = list_page(&names, &[], "tok", "/usr/local/bin/shtum", None);
        // The panel is an `<div class="secret-edit" id="edit-FOO" hidden>` —
        // toggled to visible by the inline JS when Edit is clicked.
        assert!(html.contains(r#"id="edit-FOO" hidden"#));
        assert!(html.contains(r#"data-action="toggle-edit""#));
        assert!(html.contains(r#"aria-controls="edit-FOO""#));
    }

    #[test]
    fn list_page_embeds_token_in_every_form() {
        let names = vec!["FOO".to_string()];
        let html = list_page(&names, &[], "TESTTOKEN", "/usr/local/bin/shtum", None);
        // Quick stash + add + rotate + rename + delete = 5 hidden token
        // inputs per row, with no temp keys to add Extend forms.
        let count = html.matches(r#"name="token" value="TESTTOKEN""#).count();
        assert_eq!(count, 5, "expected 5 hidden token inputs, found {count}");
    }

    #[test]
    fn list_page_renders_quick_stash_card_above_add_card() {
        let html = list_page(&[], &[], "tok", "/usr/local/bin/shtum", None);
        let quick_idx = html
            .find(r#"action="/secrets/quick""#)
            .expect("quick form must be present");
        let add_idx = html
            .find(r#"action="/secrets/add""#)
            .expect("add form must be present");
        assert!(
            quick_idx < add_idx,
            "Quick stash card ({quick_idx}) should appear before Add card ({add_idx})"
        );
        // Form has a value field and an optional ttl field, plus the
        // hidden token. No name field — names are auto-generated.
        let quick_open = html[..quick_idx]
            .rfind("<form")
            .expect("quick form must have opening tag");
        let quick_close = quick_idx
            + html[quick_idx..]
                .find("</form>")
                .expect("quick form must close");
        let quick_html = &html[quick_open..=quick_close];
        assert!(quick_html.contains(r#"name="value""#));
        assert!(quick_html.contains(r#"name="ttl""#));
        assert!(quick_html.contains(r#"name="token""#));
        assert!(!quick_html.contains(r#"name="name""#));
    }

    #[test]
    fn list_page_renders_temp_badge_only_for_tracked_rows() {
        let names = vec!["FOO".to_string(), "TMP_abc123".to_string()];
        let temp = vec![TempEntryView {
            name: "TMP_abc123".to_string(),
            expires_at: 9_999_999_999,
        }];
        let html = list_page(&names, &temp, "tok", "/usr/local/bin/shtum", None);
        // Badge exists for TMP_abc123 with the right epoch.
        assert!(html.contains(r#"data-expires-at="9999999999""#));
        // Exactly one badge — FOO is not in the temp set.
        let badge_count = html.matches(r#"class="badge badge--temp""#).count();
        assert_eq!(badge_count, 1, "expected 1 TEMP badge, found {badge_count}");
        // Extend form points at TMP_abc123, not FOO.
        assert!(html.contains(r#"action="/secrets/TMP_abc123/extend""#));
        assert!(!html.contains(r#"action="/secrets/FOO/extend""#));
    }

    #[test]
    fn list_page_temp_badge_absent_when_no_temp_entries() {
        let names = vec!["FOO".to_string()];
        let html = list_page(&names, &[], "tok", "/usr/local/bin/shtum", None);
        assert!(!html.contains(r#"class="badge badge--temp""#));
        assert!(!html.contains(r#"action="/secrets/FOO/extend""#));
    }

    #[test]
    fn list_page_extend_form_carries_token() {
        let names = vec!["TMP_abc123".to_string()];
        let temp = vec![TempEntryView {
            name: "TMP_abc123".to_string(),
            expires_at: 9_999_999_999,
        }];
        let html = list_page(&names, &temp, "EXTEND_TOK", "/usr/local/bin/shtum", None);
        // CSRF: Extend POST must include the session token.
        let extend_idx = html
            .find(r#"action="/secrets/TMP_abc123/extend""#)
            .expect("extend form must be present");
        let extend_close = extend_idx
            + html[extend_idx..]
                .find("</form>")
                .expect("extend form must close");
        let extend_html = &html[extend_idx..=extend_close];
        assert!(extend_html.contains(r#"name="token" value="EXTEND_TOK""#));
    }

    #[test]
    fn list_page_delete_form_has_confirm() {
        let names = vec!["DANGEROUS".to_string()];
        let html = list_page(&names, &[], "tok", "/usr/local/bin/shtum", None);
        assert!(html.contains(r#"onsubmit="return confirm("#));
        assert!(html.contains("DANGEROUS"));
    }

    #[test]
    fn list_page_renders_hook_snippets() {
        let html = list_page(&[], &[], "tok", "/abs/path/to/shtum", None);
        assert!(html.contains("/abs/path/to/shtum hook install"));
        assert!(html.contains("cd /path/to/your-project &amp;&amp; /abs/path/to/shtum hook install --project"));
    }

    #[test]
    fn list_page_renders_placeholder_grammar_examples_and_flags() {
        // P8b content blocks live inside the Docs panel. The render must
        // contain representative strings from each so future refactors of
        // index_page can't silently drop content.
        let html = list_page(&[], &[], "tok", "/usr/local/bin/shtum", None);

        // Placeholder reference: at least one source prefix and one mode
        // prefix from each table.
        assert!(html.contains("{kc:NAME}"), "missing {{kc:NAME}} in source-prefix table");
        assert!(html.contains("{env:NAME}"), "missing {{env:NAME}} in source-prefix table");
        assert!(html.contains("{file:PATH}"), "missing {{file:PATH}} in source-prefix table");
        assert!(html.contains("{env-inject:NAME}"), "missing {{env-inject:NAME}} in mode table");
        assert!(html.contains("{stdin:NAME}"), "missing {{stdin:NAME}} in mode table");
        assert!(html.contains("{tempfile:NAME}"), "missing {{tempfile:NAME}} in mode table");

        // Worked examples: both snippet IDs (so the copy buttons can find them).
        assert!(html.contains(r#"id="snippet-example-curl""#));
        assert!(html.contains(r#"id="snippet-example-kubectl""#));
        // And the literal commands users will copy.
        assert!(html.contains("Authorization: Bearer {CF_TOKEN}"));
        assert!(html.contains("kubectl --token={file:/run/secrets/k8s-token}"));

        // Flags reference: all four flags.
        assert!(html.contains("--dry-run"));
        assert!(html.contains("--no-auto-redact"));
        assert!(html.contains("--redact &lt;REGEX&gt;"));
        assert!(html.contains("--no-default-redact"));

        // All P8b content lives inside the Docs panel, after the
        // hook-install snippets and before the panel closes.
        let docs_open = html.find(r#"id="panel-docs""#).expect("docs panel present");
        let placeholder_idx = html.find("Placeholder reference").expect("placeholder section present");
        let flags_idx = html.find("Runtime flags").expect("flags section present");
        assert!(placeholder_idx > docs_open);
        assert!(flags_idx > placeholder_idx);
    }

    #[test]
    fn list_page_renders_tab_nav_with_keys_and_docs_panels() {
        let html = list_page(&[], &[], "tok", "/usr/local/bin/shtum", None);
        // Tablist with both tabs.
        assert!(html.contains(r#"role="tablist""#));
        assert!(html.contains(r#"id="tab-keys""#));
        assert!(html.contains(r#"id="tab-docs""#));
        // Both panels present; Docs panel starts hidden.
        assert!(html.contains(r#"id="panel-keys" role="tabpanel""#));
        assert!(html.contains(r#"id="panel-docs" role="tabpanel" aria-labelledby="tab-docs" hidden"#));
        // Hook snippets live inside the Docs panel, not the Keys panel.
        let docs_start = html.find(r#"id="panel-docs""#).expect("docs panel present");
        let keys_start = html.find(r#"id="panel-keys""#).expect("keys panel present");
        let snippets_idx = html.find("snippet-global").expect("snippets present");
        assert!(snippets_idx > docs_start, "snippets must appear after docs panel opens");
        assert!(keys_start < docs_start, "keys panel must appear before docs panel");
    }

    #[test]
    fn list_page_escapes_shtum_path_with_meta() {
        let html = list_page(&[], &[], "tok", "/weird/<path>/shtum", None);
        assert!(!html.contains("/weird/<path>/shtum"));
        assert!(html.contains("/weird/&lt;path&gt;/shtum"));
    }

    #[test]
    fn list_page_renders_info_flash() {
        let flash = Flash { kind: FlashKind::Info, message: "stored FOO" };
        let html = list_page(&[], &[], "tok", "/usr/local/bin/shtum", Some(flash));
        assert!(html.contains(r#"class="flash""#));
        assert!(html.contains("stored FOO"));
    }

    #[test]
    fn list_page_renders_error_flash_with_distinct_class() {
        let flash = Flash { kind: FlashKind::Error, message: "name rejected" };
        let html = list_page(&[], &[], "tok", "/usr/local/bin/shtum", Some(flash));
        assert!(html.contains(r#"class="flash error""#));
        assert!(html.contains("name rejected"));
    }

    #[test]
    fn list_page_omits_flash_div_when_absent() {
        let html = list_page(&[], &[], "tok", "/usr/local/bin/shtum", None);
        assert!(!html.contains(r#"class="flash""#));
    }

    #[test]
    fn error_page_includes_status_and_message_escaped() {
        let html = error_page(404, "not <found>");
        assert!(html.contains("404"));
        assert!(html.contains("not &lt;found&gt;"));
    }
}
