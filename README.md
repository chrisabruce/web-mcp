# web-mcp

An MCP server that lets Claude **search the web and read pages through a SOCKS proxy**, built on
[scrapling-rs](https://github.com/chrisabruce/scrapling-rs) (browser TLS/HTTP2 impersonation).
It can view images, log in to sites for you, and serve several people, each with their own key.
It's packaged as a Docker container for Dokploy.

## Tools

| Tool | What it does |
|---|---|
| `web_search` | Searches DuckDuckGo Lite, then falls back to Bing and DuckDuckGo HTML. Returns title, URL, and snippet for each result. |
| `fetch_url` | Fetches a page and returns its main content as `markdown` (default), `text`, or `html`. Takes an optional `css_selector`. Long pages are paged with `start` / `max_chars`. Uses your saved session for the site if you have one. |
| `fetch_image` | Downloads an image so Claude can see it. Large images are downscaled to 1568 px, formats Claude can't read (BMP, ICO) are converted, and SVGs come back as markup. |
| `site_login` | Logs in through a site's username/password form. It uses the login you saved in the admin UI, or a username and password given in the chat. The session is kept for later fetches. |
| `list_site_logins` | Lists the sites you have saved logins or sessions for. Passwords are never shown. |

All tools use `SOCKS_PROXY`. `use_login` on `fetch_url` and `fetch_image` controls sessions:
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

- **User keys** (admin only): create a named key for each person (`wmk_…`). The key is shown
  once, so copy it straight away. Each person uses their key exactly where you'd use the master
  token: as the Claude Desktop sign-in password, or as a Claude Code bearer token. **Revoke**
  works immediately on the key, its Claude Desktop sessions, and its UI sign-in.
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
  stored only as SHA-256 hashes.
- **Secrets at rest.** Saved site passwords and cookies are encrypted with ChaCha20-Poly1305
  under a key derived from `WEB_MCP_AUTH_TOKEN`, and each one is bound to its user and site.
  A copy of the database alone reveals nothing. **Rotating `WEB_MCP_AUTH_TOKEN`** signs
  everyone out and makes saved site passwords and cookies unreadable, so they must be entered
  again. User keys keep working.
- **Admin UI.** Sessions use a signed `HttpOnly; SameSite=Strict` cookie (`Secure` over HTTPS).
  Every change must come from the same origin (CSRF protection), and all output is HTML-escaped.
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

## CLI

```sh
web-mcp serve                       # Streamable HTTP server (the default)
web-mcp stdio                       # stdio transport, acting as the admin
web-mcp search rust async book      # check search (and the proxy) from the terminal
web-mcp fetch https://example.com -f text
```

## Notes

- `wreq` / `wreq-util` are pinned to exact release candidates in `Cargo.toml`, because
  scrapling-fetch doesn't compile against newer ones.
- If a site returns a plain `403` (no anti-bot vendor detected), the request is retried once
  without browser impersonation. Some sites, such as Wikimedia's file servers, reject
  impersonated browsers but serve plain clients.
- Run `make help` to list the build, test, and Docker targets.
