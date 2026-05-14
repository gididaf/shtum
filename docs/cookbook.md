# Cookbook

Copy-paste recipes for common authenticated workflows. Each recipe shows the storage step (once) and the runtime invocation (every use).

The runtime invocations work whether you call `shtum run -- ...` directly OR have the Claude Code hook installed (in which case you can let the agent write the command without the `shtum run --` prefix and the hook adds it automatically).

## Cloudflare API

**Store the token once** (create at https://dash.cloudflare.com/profile/api-tokens):

```bash
shtum store add CF_API_TOKEN
# Enter value: <paste token, hidden>
```

**List zones:**

```bash
shtum run -- curl -sH "Authorization: Bearer {CF_API_TOKEN}" \
  https://api.cloudflare.com/client/v4/zones | jq '.result[].name'
```

**Why argv mode works here:** the response is the only sensitive surface; the token in argv is visible to local `ps` but `shtum` scrubs the response. If local-ps protection matters, use a wrapper script that reads the token from env:

```bash
shtum run -- bash -c 'curl -sH "Authorization: Bearer $CF_API_TOKEN" https://api.cloudflare.com/client/v4/zones' \
  {env-inject:CF_API_TOKEN}
```

Now `curl` is invoked by bash, which expands `$CF_API_TOKEN` in-process from env — the token reaches `curl`'s argv only transiently at exec time (the limitation is intrinsic to argv-passing tools), and `ps` shows only `$CF_API_TOKEN` for the bash process itself.

## GitHub (`gh` CLI)

**Store the token** (create at https://github.com/settings/tokens):

```bash
shtum store add GH_TOKEN
```

**Authenticate via env-inject** (gh reads `GH_TOKEN` from env):

```bash
shtum run -- gh repo list {env-inject:GH_TOKEN}
shtum run -- gh pr view 42 {env-inject:GH_TOKEN}
```

**For `gh auth login --with-token`** (reads token from stdin):

```bash
shtum run -- bash -c 'gh auth login --with-token < {tempfile:GH_TOKEN}'
```

The tempfile mode writes the token to a mode-0600 file under `$TMPDIR`, substitutes the path into the command, and unlinks the file on exit.

## GitHub API (`curl`)

**Same `GH_TOKEN` store entry as above.** Direct API call:

```bash
shtum run -- curl -sH "Authorization: Bearer {GH_TOKEN}" \
  https://api.github.com/user/repos | jq '.[].full_name'
```

## AWS CLI

**Store the credentials** (one at a time):

```bash
shtum store add AWS_ACCESS_KEY_ID
shtum store add AWS_SECRET_ACCESS_KEY
shtum store add AWS_SESSION_TOKEN   # if using temporary credentials
```

**Run AWS commands** via env-inject (aws CLI reads these from env natively):

```bash
shtum run -- aws s3 ls \
  {env-inject:AWS_ACCESS_KEY_ID} \
  {env-inject:AWS_SECRET_ACCESS_KEY}

shtum run -- aws ec2 describe-instances --region us-east-1 \
  {env-inject:AWS_ACCESS_KEY_ID} \
  {env-inject:AWS_SECRET_ACCESS_KEY}
```

**Why env-inject:** the `{env-inject:NAME}` directive sets the env var and strips the placeholder from argv. The aws CLI's argv at `exec` time is just `aws s3 ls` — no credentials visible to `ps`.

## PostgreSQL (`psql`)

**Store the password:**

```bash
shtum store add PGPASSWORD
```

**Connect** (psql reads `PGPASSWORD` from env):

```bash
shtum run -- psql -h db.example.com -U myuser -d mydb \
  {env-inject:PGPASSWORD}
```

Or run a one-shot query:

```bash
shtum run -- psql -h db.example.com -U myuser -d mydb \
  -c "SELECT count(*) FROM users" \
  {env-inject:PGPASSWORD}
```

## MySQL

**Store the password:**

```bash
shtum store add MYSQL_PWD
```

**Connect** (mysql reads `MYSQL_PWD` from env):

```bash
shtum run -- mysql -h db.example.com -u myuser mydb \
  {env-inject:MYSQL_PWD}
```

> Note: MySQL CLI prints a warning when `MYSQL_PWD` is used. The warning goes to stderr; if you'd rather suppress it, redirect inside a `bash -c` wrapper.

## SSH (password auth via sshpass)

**Store the password:**

```bash
shtum store add SSH_PASS
```

**Connect via sshpass and tempfile:**

```bash
shtum run -- sshpass -f {tempfile:SSH_PASS} \
  ssh user@remote-host
```

The tempfile is created mode 0600, the path is substituted into the command, and the file is unlinked when `shtum` exits.

## Cloudflare Workers (`wrangler`)

**Store the API token:**

```bash
shtum store add CLOUDFLARE_API_TOKEN
```

**Deploy:**

```bash
shtum run -- wrangler deploy {env-inject:CLOUDFLARE_API_TOKEN}
```

**Tail logs:**

```bash
shtum run -- wrangler tail my-worker {env-inject:CLOUDFLARE_API_TOKEN}
```

## Doppler

**Store the service token:**

```bash
shtum store add DOPPLER_TOKEN
```

**Run a command with secrets injected by Doppler:**

```bash
shtum run -- doppler run -- node server.js \
  {env-inject:DOPPLER_TOKEN}
```

## OpenAI API

**Store the API key:**

```bash
shtum store add OPENAI_API_KEY
```

**Direct API call:**

```bash
shtum run -- curl -sH "Authorization: Bearer {OPENAI_API_KEY}" \
  https://api.openai.com/v1/models | jq '.data[].id'
```

## Composite recipes

### Two services in one command

`shtum` resolves all placeholders in one pass, so you can mix:

```bash
shtum run -- bash -c '
  TOKEN=$(curl -sH "Authorization: Bearer $CF_API_TOKEN" \
    https://api.cloudflare.com/client/v4/user/tokens/verify | jq -r .result.id)
  echo "Verified token id: $TOKEN"
' {env-inject:CF_API_TOKEN}
```

### Custom redaction on top of the defaults

If the API response contains other sensitive data (zone IDs, customer emails, etc.), pile on `--redact`:

```bash
shtum run \
  --redact '"zone_id":\s*"[a-f0-9]+"' \
  --redact '"email":\s*"[^"]+"' \
  -- curl -sH "Authorization: Bearer {CF_API_TOKEN}" \
  https://api.cloudflare.com/client/v4/zones
```

Both the token and any matched zone IDs / emails are replaced with `[REDACTED]` before you see the output.

### Reading a secret value from a file (no Keychain involved)

For one-off scripts or to avoid storing in Keychain:

```bash
shtum run -- curl -sH "Authorization: Bearer {file:/path/to/token.txt}" \
  https://api.example.com/whoami
```

The file's content (trailing newline stripped) is substituted. The literal value still flows through the redact filter — if it appears in the response, it gets scrubbed.

### Reading from a regular env var

```bash
CF_TEST_TOKEN=abc123 shtum run -- echo "token is {env:CF_TEST_TOKEN}"
```

The `{env:NAME}` source pulls from the parent process env (with no Keychain fallback). The bare `{NAME}` form does Keychain-first with env fallback.

## When the recipes don't fit

If your tool isn't represented here and doesn't fit cleanly into one of the four modes (argv / env-inject / stdin / tempfile), the meta-question is: **how does the tool consume the secret?**

| The tool reads the secret from… | Use mode | Example |
|---|---|---|
| An argv flag (`-H`, `-p`, `-X`) | argv (bare `{NAME}`) | `curl -H "Bearer {API_TOKEN}"` |
| An env var | `{env-inject:NAME}` | `aws ... {env-inject:AWS_ACCESS_KEY_ID}` |
| Stdin | `{stdin:NAME}` | `bash -c 'cat' {stdin:NAME}` |
| A file (by path argument) | `{tempfile:NAME}` | `sshpass -f {tempfile:NAME}` |

If a tool reads only from `~/.config/something` and provides no other input channel, you'll need to either pre-populate that file (defeats the purpose if it persists with the secret on disk) or use a wrapper that writes the file, runs the tool, and removes the file. Open an issue if you hit this — the tempfile mode could grow a `--mode=path` variant that creates a directory tree.
