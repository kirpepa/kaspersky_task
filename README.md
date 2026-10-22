# Information Exchange Service

REST API на Go для хранения информации об угрозах по MD5. PostgreSQL, генерация кода по [OpenAPI](api/openapi.yaml), HTTPS и лимит запросов по IP. Модель дополнена полями `description` и `severity`.

## Запуск

Нужны Docker с Compose v2, `make`, Unix shell и OpenSSL 1.1.1+.

```sh
make cert       # только перед первым запуском
make docker-up
```

API: `https://localhost:8443`. Для curl используйте `--cacert certs/server.crt`. Настройки — в [.env.example](.env.example).

Остановка: `make docker-down`.

## Тесты

```sh
make docker-test
```

Запускает все тесты с отдельной PostgreSQL и проверкой гонок данных.
