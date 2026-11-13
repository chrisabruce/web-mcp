# web-mcp

An MCP server that lets Claude **search the web and read pages through a SOCKS proxy**, built on
[scrapling-rs](https://github.com/chrisabruce/scrapling-rs) (browser TLS/HTTP2 impersonation).
It's packaged as a Docker container for Dokploy.

## Tools

| Tool | What it does |
|---|---|
| `web_search` | Searches DuckDuckGo Lite, then falls back to Bing and DuckDuckGo HTML. Returns title, URL, and snippet for each result. |
| `fetch_url` | Fetches a page and returns its main content as `markdown` (default), `text`, or `html`. Takes an optional `css_selector`. Long pages are paged with `start` / `max_chars`. |

## Deploy with Dokploy (Docker Compose)

1. In Dokploy, create a **Compose** service from this repository (compose file:
   `docker-compose.yml`).
2. In the **Environment** tab, set:
   ```sh
   WEB_MCP_AUTH_TOKEN=<output of: openssl rand -hex 32>   # keep this in a password manager
   WEB_MCP_PUBLIC_URL=https://mcp.example.com
   SOCKS_PROXY=socks5h://user:pass@proxy.example:1080
   ```
3. Under **Domains**, add `mcp.example.com` → service `web-mcp`, port `8787`, with HTTPS enabled.
4. Deploy, then check that `https://mcp.example.com/health` returns `ok`.

## Connect Claude

**Claude Desktop / claude.ai** (custom connector, OAuth):

1. Open **Settings → Connectors → Add custom connector**.
2. Name it `web` and enter the URL `https://mcp.example.com/mcp`. Leave the advanced OAuth fields
   empty; Claude registers itself.
3. Click **Connect**. A sign-in page from your server opens. Paste `WEB_MCP_AUTH_TOKEN` and click
   **Authorize**.
4. In a chat, enable the connector from the tools menu and ask Claude to search the web.

Claude stays signed in through 30-day refresh tokens, which renew each time they're used. To sign
every client out, rotate `WEB_MCP_AUTH_TOKEN` and redeploy.

**Claude Code** (static bearer token):

```sh
claude mcp add --scope user --transport http web https://mcp.example.com/mcp \
  --header "Authorization: Bearer <WEB_MCP_AUTH_TOKEN>"
```

The service joins the external `dokploy-network` and isn't published on the host. Traefik routes
to it. `GET /health` works without a token and is used for the container health check.

To test the image locally, copy `.env.example` to `.env`, set a token, and run
`make docker-run`. That serves on `http://127.0.0.1:8788/mcp`.

### Security

- **Auth is mandatory off-loopback.** The server refuses to start on a non-loopback address
  without `WEB_MCP_AUTH_TOKEN` (32 or more characters). Otherwise anyone who could reach it would
  have an open proxy. `/mcp` accepts either that token or an OAuth access token issued after
  someone signs in with it.
- **OAuth.** It uses authorization code + PKCE (S256) with dynamic client registration.
  Redirect URIs must be HTTPS (or loopback HTTP), and the sign-in page shows which site you'll
  be sent back to. All OAuth state lives in tokens signed with HMAC-SHA256 under a key derived
  from `WEB_MCP_AUTH_TOKEN`. Nothing is stored server-side, so sessions survive redeploys.
  Authorization codes stay valid for their 5-minute lifetime instead of being single-use; PKCE
  keeps an intercepted code useless.
- **Host allowlist.** `/mcp` rejects any `Host` header that isn't the `WEB_MCP_PUBLIC_URL` host
  or listed in `WEB_MCP_ALLOWED_HOSTS`. Set `WEB_MCP_ALLOWED_HOSTS=*` to disable the check.
- **SSRF guard.** `fetch_url` refuses `localhost` and loopback, private, link-local (including
  `169.254.169.254`), and CGNAT IP literals. It can't catch hostnames that resolve to internal
  IPs, or redirects to them. Using `SOCKS_PROXY` contains those cases, because connections then
  start from the proxy instead of your server.
- **Hardened container.** It runs as a non-root user with a read-only root filesystem, all
  capabilities dropped, and `no-new-privileges`.

## Configuration

Every setting can be given as a CLI flag, an environment variable, or a line in `.env`. See
`.env.example` for the full list.

| Variable | Default | Purpose |
|---|---|---|
| `SOCKS_PROXY` | none (direct) | `socks5h://`, `socks5://`, `socks4(a)://`, `http(s)://`. If the proxy is down, requests fail. They never fall back to a direct connection. |
| `WEB_MCP_AUTH_TOKEN` | none | Bearer token for `/mcp` and the OAuth sign-in password. |
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
web-mcp stdio                       # stdio transport: claude mcp add web -- web-mcp stdio
web-mcp search rust async book      # check search (and the proxy) from the terminal
web-mcp fetch https://example.com -f text
```

## Notes

- `wreq` / `wreq-util` are pinned to exact release candidates in `Cargo.toml`, because
  scrapling-fetch doesn't compile against newer ones.
- Run `make help` to list the build, test, and Docker targets.
