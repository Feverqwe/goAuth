# GoAuth - Yandex OAuth Authorization Service

## Description

GoAuth is an authentication proxy for Go, designed to integrate with Nginx via the `auth_request` module. It provides Yandex OAuth authentication, an IP whitelist, and flexible public path patterns.

## Key Features

- **Yandex OAuth**: External authentication provider.
- **Nginx Integration**: Works as an external authorizer via `auth_request`.
- **Public Access**: Support for domain-specific **glob patterns** (e.g., `/static/**`).
- **IP Whitelist**: Access without OAuth for individual IPv4/IPv6 addresses and CIDR networks.
- **Trusted Proxies**: Client IP resolution through `X-Forwarded-For` or `X-Real-IP` from configured proxies.
- **High Performance**: Dual **LRU caching** (for sessions and public paths).
- **Secure Sessions**: HMAC-SHA256 signed cookies with TTL.
- **Notifications**: Login alerts via Telegram.
- **YAML Config**: Easy to read and maintain configuration.

## Nginx Configuration

```nginx
server {
  listen 443 ssl;
  listen [::]:443 ssl;
  server_name app.example.com;

  location / {
    auth_request /auth;
    error_page 401 =307 https://auth.example.com/?origin=$scheme://$host$request_uri;
    proxy_pass http://backend;
  }

  location /auth {
    internal;
    proxy_pass http://goauth:8044;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header X-Original-URI $request_uri;
    proxy_set_header X-Original-Host $host;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_set_header X-Real-IP $remote_addr;
  }
}
```

## GoAuth Configuration (config.yaml)

```yaml
port: 8044
address: 0.0.0.0
name: Auth
clientId: "your_yandex_client_id"
clientSecret: "your_yandex_client_secret"
redirectUrl: "https://auth.example.com/callback"
defaultRedirectUrl: "https://example.com"
allowedRedirectDomains:
  - "*.example.com"
logins:
  - "admin_user"
ipWhitelist:
  - "192.0.2.7"
  - "198.51.100.0/24"
  - "2001:db8:1234::/48"
trustedProxies:
  - "127.0.0.1"
  - "::1"
  - "172.20.0.2" # Replace with the actual Nginx address seen by GoAuth.
cookieKey: "auth_token"
cookieSecret: "replace_with_at_least_32_random_characters"
cookieSalt: "replace_with_at_least_16_random_characters"
cookieMaxAge: 7884000
cookieDomain: ".example.com"
publicAccess:
  "api.example.com":
    - "/v1/public/**"
  "*":
    - "/favicon.ico"
    - "/robots.txt"
telegramBotToken: "your_bot_token"
telegramChatId: "your_chat_id"
```

On the first start GoAuth creates a config with random cookie credentials and exits.
Fill in the required values before restarting it. Existing configs with missing or
weak cookie credentials are rejected instead of starting with unsafe defaults.

## Redirects and OAuth Security

`allowedRedirectDomains` limits the `origin` URL used after login. Entries are
hostnames, without a scheme, port, or path. Exact names and a leading `*.` are
supported. As in goProxy, `*.rndnm.com` matches `rndnm.com`, `app.rndnm.com`, and
`one.two.rndnm.com`, but never `evilrndnm.com` or `rndnm.com.evil.org`. Matching
ignores case and a trailing DNS dot. Other glob syntax and negations are rejected.

For example:

```yaml
defaultRedirectUrl: "https://rndnm.com"
allowedRedirectDomains:
  - "*.rndnm.com"
```

Explicit domain rules allow HTTP and HTTPS URLs on any valid port for matching
hosts. Relative URLs, other schemes, userinfo, and malformed hostnames are
rejected. `defaultRedirectUrl` must also match the configured rules. If the list
is omitted or empty, only the exact origin (scheme, hostname, and effective port)
of `defaultRedirectUrl` is allowed, with any path or query. Existing deployments
that redirect to other hosts need to add those hosts or domain masks explicitly.

OAuth uses a random, single-use state valid for 10 minutes, bound to a Secure,
HttpOnly, host-only cookie with SameSite=Lax. Serve the authentication endpoint
over HTTPS. State and the destination URL are stored in memory; a restart
invalidates pending logins. Multiple instances require sticky routing from login
start through callback. Starting another login in the same browser replaces its
state cookie, so complete the latest attempt.

The token exchange and user lookup share a 10-second timeout and stop when the
incoming request is cancelled. Telegram notifications run in the background with
a 5-second timeout; at most four notifications run concurrently, and further
notifications are skipped while those slots are occupied.

Public-path checks reject dot segments (`.` and `..`), repeated slashes,
backslashes, encoded path separators, and ambiguous nested encodings before
matching or caching a public rule. Query strings do not affect path matching.

## IP Whitelist and Reverse Proxies

`ipWhitelist` grants access to `/auth` without a session cookie. Addresses outside
the list still use OAuth; public path rules continue to apply. Both `ipWhitelist`
and `trustedProxies` accept individual IPv4/IPv6 addresses and CIDR networks
(for example, `/24` or `/64`). Invalid entries prevent startup. Omitted or empty
lists disable the corresponding feature. Restart GoAuth after changing the config.

By default, GoAuth uses the connection's remote IP and ignores IP forwarding
headers. Configure `trustedProxies` with the addresses of your reverse proxies as
seen by GoAuth (including Docker bridge addresses when applicable). It then reads
`X-Forwarded-For` from right to left, skipping trusted proxy hops and using the first
untrusted address. Multiple header lines are treated as one chain. `X-Real-IP` is
used only when `X-Forwarded-For` is absent. Header values must be bare IP addresses,
without ports. A malformed address in the trusted portion of the chain disables
the IP-based grant for that request; OAuth and public path access still work.
Without either header, the connection's remote IP is used.

The Nginx example above assumes Nginx directly receives client connections and
overwrites incoming IP headers with `$remote_addr`. If another trusted proxy sits
in front of Nginx, preserve the chain using
`proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;` and configure every
trusted proxy hop in GoAuth. See the [Nginx proxy module documentation](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#var_proxy_add_x_forwarded_for).

Only list proxies you control in `trustedProxies`. Avoid `0.0.0.0/0` and `::/0`,
which would let arbitrary clients supply trusted headers. Do not whitelist proxy
addresses as client addresses: a request without forwarding headers would then
receive the proxy's access. If Nginx uses the realip module, ensure its trusted
proxy configuration agrees with GoAuth and the forwarded chain.

## API Endpoints

- `/auth` - Authorization check (used by Nginx)
- `/` - Redirect to Yandex OAuth
- `/callback` - Handler for Yandex OAuth response

## License

MIT
