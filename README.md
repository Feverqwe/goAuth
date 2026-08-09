# GoAuth - Yandex OAuth Authorization Service

## Description

GoAuth is an authentication proxy for Go, designed to integrate with Nginx via the `auth_request` module. It provides Yandex OAuth authentication and access control based on a whitelist of allowed logins and flexible public path patterns.

## Key Features

- **Yandex OAuth**: External authentication provider.
- **Nginx Integration**: Works as an external authorizer via `auth_request`.
- **Public Access**: Support for domain-specific **glob patterns** (e.g., `/static/**`).
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
logins:
  - "admin_user"
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

## API Endpoints

- `/auth` - Authorization check (used by Nginx)
- `/` - Redirect to Yandex OAuth
- `/callback` - Handler for Yandex OAuth response

## License

MIT
