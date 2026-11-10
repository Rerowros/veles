<p align="center">
  <img src="docs/veles/hero.svg" alt="Veles: ядро на базе Mihomo v1.19.33, 18 улучшений, лицензия GPL-3.0" width="100%">
</p>

<p align="center">
  <a href="https://github.com/Rerowros/veles/releases/latest"><img src="https://img.shields.io/github/v/tag/Rerowros/veles?label=%D0%B2%D0%B5%D1%80%D1%81%D0%B8%D1%8F&color=a85f00&style=flat-square" alt="Последняя версия"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/лицензия-GPL--3.0-23291f?style=flat-square" alt="Лицензия GPL-3.0"></a>
  <a href="https://github.com/MetaCubeX/mihomo"><img src="https://img.shields.io/badge/основа-Mihomo-5d6455?style=flat-square" alt="Основа: Mihomo"></a>
</p>

**Veles** — ядро на базе [Mihomo](https://github.com/MetaCubeX/mihomo). Формат конфига тот же, а сверху добавлены три вещи: REALITY, который подключается к новым серверам Xray, быстрая отправка по XHTTP и серверная часть для нод.

*English: Veles is based on Mihomo. Same config format, plus REALITY that works with current Xray servers, faster XHTTP upload and server-side features for nodes.*

## Чем отличается

<img src="docs/veles/reality-matrix.svg" alt="С настройками по умолчанию Mihomo v1.19.31 подключается только к Xray 26.3.27 и только с отпечатком. Veles подключается ко всем трём версиям Xray, к 26.9.9 со второго соединения." width="100%">

<img src="docs/veles/xhttp-upload.svg" alt="Отправка по XHTTP на тестовом сервере при интервале 30 мс: без улучшений 3,4 Мбит/с, Veles 13,2 Мбит/с." width="100%">

<img src="docs/veles/patch-map.svg" alt="18 улучшений поверх Mihomo v1.19.33: маскировка, транспорт и скорость, серверная часть." width="100%">

## Сравнение с другими ядрами

| | Veles | Mihomo v1.19.33 | Xray-core 26.10.21 |
|---|---|---|---|
| Конфиг в формате Clash, правила и группы | ✓ | ✓ | ✕ свой формат |
| TUIC, AnyTLS, Mieru | ✓ | ✓ | ✕ |
| Hysteria 2, MASQUE | ✓ | ✓ | ✓ |
| Версия клиента в REALITY | 26.11.9, настраивается | 1.8.2, не настраивается | своя |
| Отпечаток `chrome` | Chrome 155 | Chrome 133 | Chrome 133, с версии 26.11.9 — Chrome 155 |
| Подбор ML-KEM под сервер | ✓ сам | ✕ только вручную | не проверяли |
| Xray Mux: mux.cool и XUDP | ✓ | частично: сервер принимает, клиент только XUDP | ✓ |
| Транспорт xdrive | ✓ | ✕ | ✓ |
| gRPC API, совместимый с Xray | ✓ | ✕ | ✓ |
| Нарезка ClientHello | ✓ для каждого прокси | ✕ | ✓ |
| `/metrics` для Prometheus | ✓ | ✕ | ✕ есть expvar |
| Лимит IP на пользователя | ✓ | ✕ | ✕ |

Сравнение составлено по исходному коду этих версий. sing-box в таблицу не вошёл: его мы не проверяли.

## Запуск

```sh
go build -tags with_gvisor -trimpath -ldflags "-s -w" -o veles .
./veles -v
./veles -d ./config-dir
```

Настройки те же, что у Mihomo: [документация Mihomo](https://wiki.metacubex.one). Новые ключи описаны в [docs/FEATURES.md](docs/FEATURES.md).

Два отличия от Mihomo, о которых стоит знать заранее:

- без `secret` контроллер на сетевом адресе не запустится. Обойти можно настройкой `external-controller-allow-insecure`;
- неверное значение в новых ключах обычно даёт ошибку всего конфига, а не пропускается. Исключения описаны в [docs/FEATURES.md](docs/FEATURES.md).

Обновление ядра из дашборда (`POST /upgrade`) пока скачивает обычный Mihomo и заменяет им Veles, поэтому им лучше не пользоваться: новые версии берите в [релизах](https://github.com/Rerowros/veles/releases).

Для совместимости оставлены:

- `User-Agent: clash.meta/…`: по нему панели понимают, какой конфиг отдавать;
- путь модуля `github.com/metacubex/mihomo`: так проще переносить новые версии Mihomo.

## Авторы и лицензия

Veles выпускается под лицензией [GPL-3.0](LICENSE), как и Mihomo. Это изменённая версия Mihomo v1.19.33, изменения от 4 и 10 ноября 2026 года. Проект не связан с MetaCubeX и XTLS, ошибки этой сборки не надо отправлять авторам Mihomo.

Спасибо проектам, код которых здесь использован:

- [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo): основа ядра;
- [XTLS/Xray-core](https://github.com/XTLS/Xray-core), лицензия MPL-2.0: транспорт xdrive (P9), подробнее в [NOTICE](transport/xdrive/NOTICE.md), и образец для нарезки ClientHello (P19);
- [legiz-ru/Prizrak-Core](https://github.com/legiz-ru/Prizrak-Core): P1 и P15, автор Jolymmiles;
- [Nemu-x/ClashFest](https://github.com/Nemu-x/ClashFest): идея P6;
- [getmikan/Citrus](https://github.com/getmikan/Citrus): части P8 и P10, P12, P13, P14, P16 и P17;
- [refraction-networking/utls](https://github.com/refraction-networking/utls) и [metacubex/utls](https://github.com/metacubex/utls): отпечатки TLS.
