# GoAuth - Сервис авторизации через Yandex OAuth

## Описание

GoAuth - это сервер авторизации на Go, который интегрируется с Nginx через модуль `auth_request`. Сервис предоставляет возможность аутентификации пользователей через Yandex OAuth и управление доступом на основе списка разрешенных логинов.

## Основные возможности

- Аутентификация через Yandex OAuth
- Интеграция с Nginx через auth_request
- Уведомления о новых входах через Telegram
- Управление списком разрешенных пользователей
- Подпись и проверка cookies для сессий

## Конфигурация Nginx

Пример конфигурации Nginx для работы с GoAuth:

```nginx
server {
  listen 443 ssl;
  listen [::]:443 ssl;

  server_name example.com;

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
  }
}
```

## Конфигурация GoAuth

Конфигурационный файл `config.json` содержит следующие параметры:

```json
{
  "port": 8044,
  "address": "0.0.0.0",
  "name": "Auth",
  "clientId": "your_yandex_client_id",
  "clientSecret": "your_yandex_client_secret",
  "redirectUrl": "https://auth.example.com/callback",
  "defultRedirectUrl": "https://example.com",
  "logins": ["allowed_user1", "allowed_user2"],
  "cookieKey": "auth_token",
  "cookieSecret": "secure_secret",
  "cookieSalt": "secure_salt",
  "cookieMaxAge": 7884000,
  "cookieDomain": ".example.com",
  "telegramBotToken": "your_bot_token",
  "telegramChatId": "your_chat_id"
}
```

## Запуск через Docker

1. Соберите образ:
```bash
docker build -t goauth .
```

2. Запустите контейнер:
```bash
docker run -d \
  -p 8044:8044 \
  -v /path/to/config:/config \
  --name goauth \
  goauth
```

## Локальная разработка

Для сборки и запуска локально:

```bash
# Сборка
./scripts/build.sh

# Запуск
./scripts/run.sh
```

## API Endpoints

- `/auth` - Проверка авторизации (используется Nginx)
- `/` - Перенаправление на Yandex OAuth
- `/callback` - Обработчик callback от Yandex OAuth

## Зависимости

- Go 1.23+
- Docker (для контейнеризации)

## Лицензия

MIT
