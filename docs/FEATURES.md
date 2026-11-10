# Новые ключи Veles

Обычный Mihomo эти ключи молча пропускает. Veles на неверное значение обычно отвечает ошибкой всего конфига. Исключение: плохой `fallback-page` не даёт запуститься только этому входу, и видно это при старте.

## Прокси

| Ключ | Что делает |
|---|---|
| `reality-opts.client-version: "x.y.z"` | Версия клиента в REALITY. По умолчанию 26.11.9 |
| `reality-opts.mlkem-client-fingerprint` | Отпечаток для рукопожатий с ML-KEM |
| `fragment-opts` | Нарезка начала TLS-соединения: `packets`, `length`, `delay`, `max-split` |
| `mux.cool` | Xray Mux и XUDP, только для `type: vless` |
| `network: xdrive` и `xdrive-opts` | Транспорт xdrive. С Xray-core 26.11.9 проверен только режим `local` |

Если у REALITY не задан `support-x25519mlkem768`, ядро само подбирает ML-KEM под каждый сервер. Если `client-fingerprint` пустой, используется `chrome`.

`client-fingerprint: chrome` — это Chrome 155, как у Xray-core с версии 26.11.9. Прежний отпечаток Chrome 133 доступен под именем `chrome133`, новый можно задать и явно: `chrome155`. Обычный Mihomo этих двух имён не знает.

## Сервер

| Ключ | Что делает |
|---|---|
| `listeners[].fallback-page` | HTML-страница для чужих запросов, файл до 1 МБ. Только vless через ws, grpc или xhttp и trojan через ws или grpc |
| `listeners[].proxy-protocol`, `proxy-protocol-trusted` | PROXY protocol за балансировщиком |
| `listeners[].xdrive-config` | Вход xdrive |
| `xray-api.listen` | gRPC API, совместимый с Xray |
| `user-limits` | Список лимитов. В каждой записи обязательны `inbound` и `user`, дальше `max-conns`, `max-ips`, `up-bps`, `down-bps`, `quota`, `expire-at` |
| `metrics.enable`, `metrics.per-user` | `/metrics` в формате Prometheus |
| `health-without-auth` | `/healthz` и `/readyz` без авторизации |
| `external-controller-allow-insecure` | Контроллер на сетевом адресе без `secret` |
