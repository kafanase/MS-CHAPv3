# MS-CHAPv3 proxy

Прокси-протокол с взаимной парольной аутентификацией MS-CHAPv3 (SCRAM-подобная
схема, см. `mschapv3/mschapv3.go`), работающий поверх TLS 1.3 или (если TLS
выключен) поверх собственного AEAD-слоя.

> Это самодельный протокол. Он не проходил независимый криптоаудит. Для
> критичных задач используйте проверенные решения (WireGuard, Xray/REALITY, SSH, IKEv2).

## Состав

| Файл | Назначение |
|---|---|
| `dist/mschapv3-server-linux-{amd64,arm64}` | сервер для Linux, настройка через `config.json` |
| `dist/mschapv3-client-termux-{arm64,arm}` | клиент для Termux: локальный SOCKS5 (+HTTP) |
| `dist/mschapv3-client-windows-{amd64,arm64}.exe` | клиент для Windows: локальный прокси + системный прокси |
| `deploy/` | примеры конфигов, systemd-юнит |
| `build.sh` | пересборка из исходников (Go ≥ 1.22, без внешних зависимостей) |

## Сервер (Linux)

```sh
cp dist/mschapv3-server-linux-amd64 /usr/local/bin/mschapv3-server
mkdir -p /etc/mschapv3 && cd /etc/mschapv3

mschapv3-server -genconfig                 # создаёт config.json (с секретом)
mschapv3-server -gencert example.com       # self-signed сертификат + pin_sha256 для клиента
mschapv3-server -adduser alice             # пароль сгенерируется и покажется один раз
mschapv3-server -c config.json             # запуск
```

Вместо self-signed можно положить настоящий сертификат (Let's Encrypt) в
`tls.cert` / `tls.key`. Тогда клиенту не нужен `pin_sha256`.

`config.json`:

| Поле | Смысл |
|---|---|
| `listen` | адрес и порт (для 443 нужен root или `CAP_NET_BIND_SERVICE`) |
| `tls.enabled/cert/key` | TLS 1.3. Без TLS работает встроенное AEAD-шифрование |
| `fallback` | куда отправлять всё, что не похоже на наш протокол (браузеры, сканеры), например локальный сайт `127.0.0.1:8080` |
| `kdf_iterations` | итерации PBKDF2 для новых пользователей (по умолчанию 600000) |
| `allow_private_targets` | `false` — запретить клиентам ходить в localhost/LAN/CGNAT сервера |
| `connect_timeout_sec` | таймаут соединения с целью |
| `log_targets` | писать в лог адреса назначения (по умолчанию выключено ради приватности) |
| `secret` | для одинаковых «фиктивных» ответов по несуществующим пользователям |
| `users` | записи-верификаторы; **пароли в конфиге не хранятся** |

Пользователей добавляют и удаляют (`-adduser`, `-deluser`) при работающем
сервере, затем `systemctl reload mschapv3-server` (SIGHUP). Юнит лежит в
`deploy/mschapv3-server.service`.

Защита от перебора: после 10 неудачных входов за 5 минут IP блокируется.
Каждая проверка у атакующего требует и вычисления PBKDF2 на его стороне.

## Клиент для Termux (SOCKS5)

```sh
cp client.termux.example.json client.json    # впишите server, username, password, pin_sha256
chmod +x mschapv3-client-termux-arm64
./mschapv3-client-termux-arm64 -c client.json
# в другой сессии:
export ALL_PROXY=socks5h://127.0.0.1:1080
curl https://ifconfig.me
```

* `dns` нужен, потому что в Termux нет `/etc/resolv.conf` и Go не сможет найти
  адрес сервера. Если в `server` указан IP, поле не нужно.
* Для сертификата Let's Encrypt в Termux: `export SSL_CERT_FILE=$PREFIX/etc/tls/cert.pem`
  (или используйте `pin_sha256`).
* `socks5h://` (с буквой h) передаёт имена серверу, DNS-запросы не утекают.

## Клиент для Windows

```
mschapv3-client-windows-amd64.exe -c client.json
```

Клиент поднимает локальный прокси (SOCKS5 + HTTP на одном порту, по умолчанию
`127.0.0.1:1081`), включает **системный прокси Windows** и при выходе (Ctrl+C)
возвращает прежние настройки. Если процесс убили жёстко и прокси «завис»:
`mschapv3-client-windows-amd64.exe -unset`. Флаг `-no-sysproxy` — не трогать
настройки системы (например, чтобы указать SOCKS5 вручную в браузере).

Системный прокси применяют браузеры и приложения, использующие WinINet/WinHTTP;
программы, которые его игнорируют, работают напрямую.

## Как это устроено

```
C→S  ClientFirst   user, cnonce, X25519 pub
S→C  ServerFirst   salt, iterations, snonce, X25519 pub
C→S  ClientFinal   proof        (+ запрос на соединение сразу следом, экономия RTT)
S→C  ServerFinal   подпись сервера (взаимная аутентификация)
S→C  статус (1 байт), далее поток данных
```

* В БД сервера лежат `StoredKey`/`ServerKey`, а не пароль и не NT-hash: утечка
  конфига не позволяет войти от имени пользователя.
* TLS-режим: channel binding (TLS exporter) входит в аутентификацию, MITM-релей
  невозможен.
* Режим без TLS: эфемерный X25519 (forward secrecy) и AES-256-GCM с раздельными
  ключами направлений, счётчиками nonce и авторизованным признаком конца
  потока (обрыв/усечение детектируется).
* Один проксируемый поток = одно соединение; PBKDF2 на клиенте считается один
  раз и кэшируется.

## Ограничения (честно)

* Только TCP (SOCKS5 UDP ASSOCIATE не поддержан).
* Без TLS протокол легко опознать (фиксированный префикс, имя пользователя в
  открытом виде). Для скрытности используйте TLS + настоящий сертификат +
  `fallback` на реальный сайт.
* Отпечаток TLS-клиента у Go стандартный (не браузерный): для устойчивости к
  DPI нужна имитация через uTLS, в сборку без внешних зависимостей она не входит.
* Fallback срабатывает на «не наш протокол». Тот, кто знает формат протокола,
  может отличить сервер по поведению.
* Слабый пароль можно подобрать офлайн по перехваченному хендшейку (в режиме
  без TLS). Используйте длинные пароли (сгенерированные `-adduser` подходят).
* Нормализация пароля (SASLprep) не выполняется: используйте ASCII.
