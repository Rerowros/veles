# Новые ключи Veles

Обычный Mihomo эти ключи молча пропускает. Veles на неподдерживаемое или конфликтное значение ключа прокси пишет предупреждение в лог и пропускает только сам ключ, не роняя профиль (как оригинальный Mihomo). Строгая проверка оставлена только у серверных лимитов `user-limits` и `proxy-protocol`; плохой `fallback-page` не даёт запуститься только этому входу при старте.

## Прокси

| Ключ | Что делает |
|---|---|
| `reality-opts.client-version: "x.y.z"` | Версия клиента в REALITY. По умолчанию 26.11.9 |
| `reality-opts.mlkem-client-fingerprint` | Отпечаток для рукопожатий с ML-KEM |
| `fragment-opts` | Нарезка начала TLS-соединения: `packets`, `length`, `delay`, `max-split`. Работает и у `type: direct` |
| `mux.cool` | Xray Mux и XUDP, только для `type: vless` без `flow: xtls-rprx-vision` |
| `network: xdrive` и `xdrive-opts` | Транспорт xdrive. С Xray-core 26.11.9 проверен только режим `local` |

Если у REALITY не задан `support-x25519mlkem768`, ядро само подбирает ML-KEM под каждый сервер.

Если `client-fingerprint` пустой — у REALITY и у обычного TLS (vless, vmess, trojan, WebSocket, gRPC, XHTTP) — используется `chrome` через uTLS, как у Xray-core. Имя отпечатка читается без учёта регистра; неизвестное имя даёт одно предупреждение в лог и `chrome`. `client-fingerprint: none` оставляет стандартный TLS Go (у REALITY это ошибка). `random` выбирает только chrome, safari или firefox.

Vision (`flow: xtls-rprx-vision`) добавляет случайный хвост и к крупным первым пакетам, как Xray-core.

`client-fingerprint: chrome` — это Chrome 155, как у Xray-core с версии 26.11.9. Прежний отпечаток Chrome 133 доступен под именем `chrome133`, новый можно задать и явно: `chrome155`. Обычный Mihomo этих двух имён не знает.

## Импорт ссылок Xray

Новых ключей нет. Из ссылки берутся SNI, отпечаток и ключ REALITY канала скачивания (`downloadSettings`), а также его `pinnedPeerCertSha256` и `verifyPeerCertByName`. `pcs` и `vcn` принимают список через запятую, `vcn` импортируется в `name-cert-verify`. Если у канала скачивания свой `tlsSettings` или SNI, он не перенимает `skip-cert-verify` основной ссылки и проверяет сертификат.

## Диагностика подключений

На контроллере добавлен кольцевой журнал последних 256 непрошедших исходящих подключений (TCP и UDP, кроме намеренных правил `REJECT`):

- `GET /connections` — поля `failedTotal` и `failedConnections`;
- `GET /connections/failed` — снимок JSON (`?limit=N`) или поток WebSocket (`?interval=1000`);
- `DELETE /connections/failed` — очистка буфера;
- `GET /events?types=dial.error` — поток событий ошибок дозвона;
- `GET /metrics` — счётчик `mihomo_dial_failures_total`.

## Скачивание подписок и провайдеров

Новых ключей нет. При переадресации загрузчик (подписка, proxy- и rule-providers, geo-данные, обновления) не отправляет `Referer`, а если цепочка ушла на другой хост — снимает заголовки `X-*` до конца цепочки, кроме заголовков устройства: `x-hwid`, `x-device-os`, `x-ver-os`, `x-device-model` и `x-app-version` (без учёта регистра). Прямой запрос уходит как задан.

При `alpn: [http/1.1]` и отпечатке uTLS (например, XHTTP) ClientHello не несёт ALPS(h2) и ALPN h2, как уже было у WebSocket.

## Телефоны

Новых ключей нет, ядро само ведёт себя бережнее к батарее и памяти:

- на iOS, как и на Android, не шлёт TCP keepalive, что бы ни стояло в `disable-keep-alive`;
- на iOS hysteria, hysteria2 и tuic не шлют QUIC-пинг каждые 10 секунд; явный `heartbeat-interval` у tuic по-прежнему работает;
- счётчик скорости засыпает через 5 секунд без трафика и просыпается от первого байта;
- в сборке с тегом `with_low_memory` окна приёма QUIC (hysteria, hysteria2, tuic, shadowquic) ограничены 2 МБ на поток и 4 МБ на соединение.

## Сервер

| Ключ | Что делает |
|---|---|
| `listeners[].fallback-page` | HTML-страница для чужих запросов, файл до 1 МБ. Только vless через ws, grpc или xhttp и trojan через ws или grpc |
| `listeners[].proxy-protocol`, `proxy-protocol-trusted` | PROXY protocol за балансировщиком |
| `listeners[].xdrive-config` | Вход xdrive |
| `xray-api.listen` | gRPC API, совместимый с Xray |
| `user-limits` | Список лимитов. В каждой записи обязательны `inbound` и `user`, дальше `max-conns`, `max-ips`, `up-bps`, `down-bps`, `quota`, `expire-at` |

Пакетная отправка в relay (чтение наперёд и одна запись `writev` на пачку) включается только тегом сборки `with_relay_batch`. Она ускоряет relay, когда он упирается в процессор (несколько Гбит/с, нагруженный сервер); на клиенте до 1 Гбит/с скорость та же, а памяти и процессора уходит больше. Выпуски собраны без этого тега.
| `metrics.enable`, `metrics.per-user` | `/metrics` в формате Prometheus |
| `health-without-auth` | `/healthz` и `/readyz` без авторизации |
| `external-controller-allow-insecure` | Контроллер на сетевом адресе без `secret` |
