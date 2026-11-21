# Доступы и параметры

Создать файлы:

```text
python <skill>/scripts/control.py init --dir <LOCAL>/VPN-Automation
```

На Windows предпочтительно `$env:LOCALAPPDATA\VPN-Automation`, на Linux/macOS `~/.local/share/vpn-automation`. Не использовать OneDrive/Dropbox/Git для секретов по умолчанию. Init не перезаписывает существующие файлы. Windows ACL helper не меняет: агент должен проверить наследуемые права локальной папки и при необходимости ограничить их текущим пользователем и SYSTEM средствами Windows; не обещать защиту только chmod.

Пользователь редактирует `servers.private.json` локально в редакторе. Адреса — IP или DNS-имена без `https://`, путей и `root@`. Для каждой роли заполняется **один** способ авторизации:

```json
{
  "schema_version": 1,
  "servers": {
    "ru": {
      "host": "203.0.113.10",
      "port": 22,
      "username": "root",
      "auth": {"type": "password", "password": "ВВЕДИТЕ_ЛОКАЛЬНО"},
      "host_key_sha256": "SHA256:ПРОВЕРЕННЫЙ_ОТПЕЧАТОК"
    },
    "exit": {
      "host": "198.51.100.20",
      "port": 22,
      "username": "root",
      "auth": {
        "type": "key",
        "private_key_path": "C:/Users/NAME/.ssh/id_ed25519",
        "passphrase": ""
      },
      "host_key_sha256": ""
    }
  }
}
```

Примеры IP выше — адреса документации, а не рабочие серверы. Пустой fingerprint допускается только с доверенным known_hosts на машине агента. Получить fingerprint в доверенной консоли VPS: `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`. Если SSH выбирает другой host-key algorithm, сверить соответствующий публичный host key. Никогда не менять доверенный отпечаток после mismatch без независимой проверки.

Пути ключей поддерживают `~`, абсолютный путь или путь относительно файла JSON. В Windows JSON используйте `/` или двойной `\\`. Пароль может содержать спецсимволы, но должен быть корректно экранирован JSON; helper передаёт его API, не shell.

`plan.json` не содержит паролей:

- `mode`: install / repair / audit / backup / restore; по умолчанию repair.
- `allow_reboot`: false по умолчанию; true разрешает последовательную перезагрузку и проверку обоих VPS после успешных предварительных тестов. Для текущего запроса можно использовать уже данное разрешение.
- `services`: chatgpt, claude, gemini, youtube, instagram, telegram.
- `clients`: ios, android, windows, macos — только необходимые пользователю платформы.
- `amnezia_container`: auto — обнаружить, не выдумывать существование.
- `ipv6_policy`: ipv4-only — запретить IPv6-обход в VPN-профилях и проверить; если текущий профиль это не позволяет, явно отразить ограничение и исправить совместимым способом.

Покупка серверов не входит в скилл. Для схемы нужен российский публично доступный вход (не NAT без нужного UDP-проброса), root/sudo и зарубежный VPS. В helper автоматизирован root; non-root требует отдельно проверенного способа sudo без помещения sudo-пароля в командную строку. Если Amnezia ещё не установлена, агент должен установить её официальным способом с учётом версии клиента, а не молча сменить продукт.

Команды helper:

```text
python scripts/control.py validate --config <file>
python scripts/control.py scan --config <file> --server ru
python scripts/control.py run --config <file> --server ru --script <local.sh>
python scripts/control.py get --config <file> --server ru --remote /root/vpn-backups/file.tar.gz --local <local-file>
python scripts/control.py put --config <file> --server ru --local <local-file> --remote /root/vpn-automation/file
```

Для run/get/put/scan установить в локальный venv `paramiko>=3.5,<5`; не изменять системный Python без необходимости. Run запускает файл через `bash -s`, поэтому bash-скрипты не проходят через кавычки PowerShell. Не включать `set -x`, не печатать `wg showconf`, raw docker inspect или ключи в stdout. Helper маскирует известные секреты авторизации, но не может распознавать все вновь сгенерированные секреты: сохранять их в закрытых файлах и скачивать через get.
