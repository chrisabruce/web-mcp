# web-mcp

An MCP server that lets Claude **search the web and read pages through a SOCKS proxy**, built on
[scrapling-rs](https://github.com/chrisabruce/scrapling-rs) (browser TLS/HTTP2 impersonation).
It can view images, log in to sites for you, send email with attachments from your account, and
serve several people, each with their own key.
It's packaged as a Docker container for Dokploy.

## Tools

| Tool | What it does |
|---|---|
| `web_search` | Searches DuckDuckGo Lite, then falls back to Bing and DuckDuckGo HTML. Returns title, URL, and snippet for each result. |
| `fetch_url` | Fetches a page and returns its main content as `markdown` (default), `text`, or `html`. Takes an optional `css_selector`. Long pages are paged with `start` / `max_chars`. Uses your saved session for the site if you have one. |
| `fetch_image` | Downloads an image so Claude can see it. Large images are downscaled to 1568 px, formats Claude can't read (BMP, ICO) are converted, and SVGs come back as markup. |
| `site_login` | Logs in through a site's username/password form. It uses the login you saved in the admin UI, or a username and password given in the chat. The session is kept for later fetches. |
| `list_site_logins` | Lists the sites you have saved logins or sessions for. Passwords are never shown. |
| `send_email` | Sends an email from your account (see [Email](#email)). Attachments can be text Claude writes, a file downloaded from a URL through the proxy (logged in if you have a session), or a file from Claude's own workspace (see [Attaching files from Claude's workspace](#attaching-files-from-claudes-workspace)). Only listed when email is configured. |
| `create_upload` | Returns a single-use upload URL so Claude can `curl` a workspace file to the server and attach it by `upload_id`. Only listed when email is configured. |

All web traffic uses `SOCKS_PROXY` (email goes straight to Fastmail). `use_login` on `fetch_url` and `fetch_image` controls sessions:
leave it out to use a saved session if one exists, set `true` to require one (logging in with
the saved password if needed), or `false` to fetch anonymously.

## Deploy with Dokploy (Docker Compose)

1. In Dokploy, create a **Compose** service from this repository (compose file:
   `docker-compose.yml`).
2. In the **Environment** tab, set:
   ```sh
   WEB_MCP_AUTH_TOKEN=<output of: openssl rand -hex 32>   # the admin key; keep it in a password manager
   WEB_MCP_PUBLIC_URL=https://mcp.example.com
   SOCKS_PROXY=socks5h://user:pass@proxy.example:1080
   ```
3. Under **Domains**, add `mcp.example.com` → service `web-mcp`, port `8787`, with HTTPS enabled.
4. Deploy, then check that `https://mcp.example.com/health` returns `ok`.

The compose file mounts a `web-mcp-data` volume at `/data` for the SQLite database (user keys,
saved logins, sessions). Keep that volume when you redeploy.

## Admin UI and user keys

Open `https://mcp.example.com/admin` and sign in with `WEB_MCP_AUTH_TOKEN`.

- **User keys** (admin only): create a named key for each person (`wmk_…`). Click **Show** to
  view a key at any time. Each person uses their key exactly where you'd use the master token:
  as the Claude Desktop sign-in password, or as a Claude Code bearer token. **New key** replaces a
  key, and the old one stops working at once. **Revoke** disables the user immediately: their
  key, their Claude Desktop sessions, and their UI sign-in.
- **Site logins** (everyone, with their own key): each user manages their own sites here.
  - **Save a username & password**: Claude then logs in on demand (`site_login`, or
    `use_login: true`). This works for normal HTML login forms, including ones with hidden CSRF
    tokens.
  - **Import browser cookies**: for sites that log in with JavaScript, CAPTCHAs, or 2FA, which
    no plain HTTP client can complete. Log in with your own browser, then paste the site's
    cookies: a `Cookie:` header from developer tools, a Cookie-Editor JSON export, or
    `cookies.txt`.

Sessions and logins are private to each key. Passwords and cookies are encrypted at rest and
never shown again.

## Email

`send_email` sends from one account: yours. To enable it with Fastmail:

1. In Fastmail, go to **Settings → Privacy & Security → Manage API tokens** and create a token
   with **Email** and **Email submission** access. (Read-only won't do.)
2. Set these in Dokploy's **Environment** tab and redeploy:
   ```sh
   FASTMAIL_API_TOKEN=fmu1-...
   MAIL_FROM="Your Name <you@yourdomain.com>"   # optional; defaults to your primary address
   MAIL_BCC=someone@example.com                  # optional; an extra copy of everything sent
   ```
   `MAIL_FROM` must be one of your Fastmail sending identities (Settings → Sending
   identities). An address on a domain with a `*@domain` identity also works.
3. Check the logs for `email enabled from=…`. Problems show up as `account check failed` with the
   reason: a rejected token, a missing scope, or a `MAIL_FROM` you can't send as (with your
   identities listed). From a shell you can also run `web-mcp test-email you@example.com`.

Mail is sent through Fastmail's JMAP API, so every message Claude sends is saved in your
**Sent** folder.

Who can send:

- **The admin** (master token) can always send.
- **Other users** can't until you click **Allow** in the **Email** column under **User keys**.
  They then send as `MAIL_FROM` too, so only allow people you trust with your address.

### Attaching files from Claude's workspace

Claude's workspace (where it writes files like `/mnt/user-data/outputs/report.pdf`) is a
different machine from this server, so the server can't read those paths. `send_email`
supports three ways to move the bytes, and its tool description tells Claude to try them in
this order:

1. **File reference (`content`).** Claude puts `sha256:<hash>:<path>` in the attachment's
   `content` field, the same convention the Gmail connector uses. If the Claude app replaces
   the reference with the file's bytes before calling the tool, nothing else is needed. If it
   doesn't, the server refuses the unreplaced reference with a clear error and Claude moves
   on, so a broken attachment is never sent.
2. **Upload (`create_upload` + `upload_id`).** Claude calls `create_upload`, runs the
   `curl -T <file> <url>` command it returns, and attaches the file by `upload_id`. The URL is
   a random single-use link that expires after an hour, accepts one file up to
   `MAIL_MAX_ATTACHMENT_MB`, and is the only credential involved (no key goes into the
   shell). Uploads are held in memory, only the uploader can attach them, and they are
   dropped once sent. Claude's sandbox only reaches allowed domains, so you may need to add
   your server's domain (e.g. `mcp.example.com`) to the allowed domains under claude.ai
   **Settings → Capabilities**.
3. **`base64`.** Claude types the bytes into the call. Only practical for small files.

`text` (contents Claude writes) and `url` (files on the web) work as before and need none of
this.

Limits: by default 2 recipients (to + cc + bcc) and 25 MB of attachments per message; change
them with `MAIL_MAX_RECIPIENTS` and `MAIL_MAX_ATTACHMENT_MB`. Each sent email is logged with the
user, recipients, attachment count, and Message-ID. Claude Desktop asks before running `send_email`
unless you've set it to always allow.

## Connect Claude

**Claude Desktop / claude.ai** (custom connector, OAuth):

1. Open **Settings → Connectors → Add custom connector**.
2. Name it `web` and enter the URL `https://mcp.example.com/mcp`. Leave the advanced OAuth fields
   empty; Claude registers itself.
3. Click **Connect**. A sign-in page from your server opens. Paste your key (your `wmk_…` user
   key, or `WEB_MCP_AUTH_TOKEN` for the admin) and click **Authorize**.
4. In a chat, enable the connector from the tools menu and ask Claude to search the web.

Claude stays signed in through 30-day refresh tokens, which renew each time they're used.
Revoking a user's key signs that user out.

**Claude Code** (static bearer token):

```sh
claude mcp add --scope user --transport http web https://mcp.example.com/mcp \
  --header "Authorization: Bearer <your key>"
```

The service joins the external `dokploy-network` and isn't published on the host. Traefik routes
to it. `GET /health` works without a token and is used for the container health check.

To test the image locally, copy `.env.example` to `.env`, set a token, and run
`make docker-run`. That serves on `http://127.0.0.1:8788/mcp`.

### Security

- **Auth is mandatory.** The server won't start without `WEB_MCP_AUTH_TOKEN` (32 or more
  characters). `/mcp` accepts the master token, an active user key, or an OAuth access token,
  and checks the user on every request, so a revocation applies immediately. User keys are
  looked up by SHA-256 hash and also stored encrypted, so the admin can view them.
- **Secrets at rest.** User keys, saved site passwords, and cookies are encrypted with ChaCha20-Poly1305
  under a key derived from `WEB_MCP_AUTH_TOKEN`, and each one is bound to its user and site.
  A copy of the database alone reveals nothing. **Rotating `WEB_MCP_AUTH_TOKEN`** signs
  everyone out and makes saved site passwords and cookies unreadable, so they must be entered
  again. User keys keep working but can't be displayed until you issue a **New key**.
- **Admin UI.** Sessions use a signed `HttpOnly; SameSite=Strict` cookie (`Secure` over HTTPS).
  Every change must come from the same origin (CSRF protection), and all output is HTML-escaped.
- **Email.** The API token is never logged. Messages go directly to Fastmail's JMAP API over
  HTTPS, not through the proxy. Sending is limited to the
  admin and users the admin has allowed.
- **Uploads.** `PUT /uploads/{token}` needs no bearer token. The 256-bit random token in the URL
  is the credential (only its hash is kept), and it works once, expires after an hour, and is
  issued only to users allowed to send email. Files stay in memory, bound to their uploader.
  The route only exists when email is configured.
- **Passwords in chat.** Passing a username and password to `site_login` sends them through
  your Claude conversation. Saving them in the admin UI keeps them out of chats.
- **OAuth.** It uses authorization code + PKCE (S256) with dynamic client registration.
  Redirect URIs must be HTTPS (or loopback HTTP), and the sign-in page shows which site you'll
  be sent back to. All OAuth state lives in tokens signed with HMAC-SHA256 under a key derived
  from `WEB_MCP_AUTH_TOKEN`. Nothing is stored server-side, so sessions survive redeploys.
  Authorization codes stay valid for their 5-minute lifetime instead of being single-use; PKCE
  keeps an intercepted code useless.
- **Host allowlist.** `/mcp` rejects any `Host` header that isn't the `WEB_MCP_PUBLIC_URL` host
  or listed in `WEB_MCP_ALLOWED_HOSTS`. Set `WEB_MCP_ALLOWED_HOSTS=*` to disable the check.
- **SSRF guard.** Every request, and every redirect hop, refuses `localhost` and loopback,
  private, link-local (including `169.254.169.254`), and CGNAT IP literals. It can't catch
  hostnames that resolve to internal IPs. Using `SOCKS_PROXY` contains that case, because
  connections then start from the proxy instead of your server.
- **Hardened container.** It runs as a non-root user with a read-only root filesystem, all
  capabilities dropped, and `no-new-privileges`.

## Configuration

Every setting can be given as a CLI flag, an environment variable, or a line in `.env`. See
`.env.example` for the full list.

| Variable | Default | Purpose |
|---|---|---|
| `SOCKS_PROXY` | none (direct) | `socks5h://user:pass@host:port`, or the provider format `socks5h://host:port:user:pass`. Also `socks5://`, `socks4(a)://`, `http(s)://`. If the proxy is down, requests fail. They never fall back to a direct connection. |
| `WEB_MCP_AUTH_TOKEN` | none (required) | The admin key, and the root of the token-signing and storage-encryption keys. |
| `WEB_MCP_DATA_DIR` | `data` (`/data` in Docker) | SQLite database location. |
| `WEB_MCP_PUBLIC_URL` | none | Public HTTPS base URL. Enables OAuth. |
| `WEB_MCP_ALLOWED_HOSTS` | `localhost,127.0.0.1,::1` | Extra accepted `Host` headers. |
| `WEB_MCP_BIND` | `127.0.0.1:8787` (`0.0.0.0:8787` in Docker) | Listen address. |
| `WEB_MCP_TIMEOUT_SECS` / `WEB_MCP_RETRIES` | `30` / `2` | Per-request timeout and attempts. |
| `WEB_MCP_MAX_CHARS` | `40000` | Default page content cap per call. |
| `WEB_MCP_IMPERSONATE` | `chrome` | `chrome`, `firefox`, `safari`, `edge`, or `none`. |
| `WEB_MCP_SEARCH_ENGINES` | `duckduckgo-lite,bing,duckduckgo-html` | Engines to try, in order. |
| `FASTMAIL_API_TOKEN` | none (email off) | Fastmail API token with Email and Email submission access. |
| `JMAP_SESSION_URL` | `https://api.fastmail.com/jmap/session` | JMAP server (for non-Fastmail JMAP providers). |
| `MAIL_FROM` | primary identity | Sender, e.g. `Name <me@example.com>`; must be a sending identity. |
| `MAIL_BCC` | none | Gets a blind copy of every message sent. |
| `MAIL_MAX_RECIPIENTS` | `2` | Most recipients (to + cc + bcc) per email. `MAIL_BCC` isn't counted. |
| `MAIL_MAX_ATTACHMENT_MB` | `25` | Most attachment megabytes per email. |

## CLI

```sh
web-mcp serve                       # Streamable HTTP server (the default)
web-mcp stdio                       # stdio transport, acting as the admin
web-mcp search rust async book      # check search (and the proxy) from the terminal
web-mcp fetch https://example.com -f text
web-mcp test-email you@example.com  # check the email settings
```

## Notes

- `wreq` / `wreq-util` are pinned to exact release candidates in `Cargo.toml`, because
  scrapling-fetch doesn't compile against newer ones.
- If a site returns a plain `403` (no anti-bot vendor detected), the request is retried once
  without browser impersonation. Some sites, such as Wikimedia's file servers, reject
  impersonated browsers but serve plain clients.
- If a site resets the HTTP/2 stream (a refusal some anti-bot systems use instead of a status
  code), the request is retried once as Safari on iPhone. Best Buy product pages, for example,
  reset every desktop browser fingerprint but serve iOS. This needs a scrapling-fetch build
  that knows the `safari_ios` profile.
- Run `make help` to list the build, test, and Docker targets.
