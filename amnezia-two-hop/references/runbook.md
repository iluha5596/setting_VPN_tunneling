# Runbook: обследование, развёртывание, проверка

## 0. Рабочая схема и факты

Клиент AmneziaWG → RU Docker-контейнер → host policy routing → обычный WireGuard RU↔EXIT → NAT на EXIT. Обычные назначения выходят с RU. DNS выбранных доменов наполняет IPv4 ipset; пакет маркируется по назначению и уходит в отдельную таблицу. Это не универсальное распознавание приложений и не гарантия обхода «белых списков».

Историческая успешно проверенная конфигурация (не новые targets): Ubuntu 24.04, российский VPS и EXIT DigitalOcean AMS3, wg-do 10.77.78.2/30 на RU и .1/30 на EXIT, UDP51820 межсерверный, AWG UDP37268. Table17778, fwmark0x1000000/0x1000000, приоритеты17771 и17778. Восстановилась после reboot; iPhone ChatGPT/Instagram проверены пользователем на Wi-Fi и мобильной сети 2026-11-21. Android ещё не проверен. Публичные адреса серверов намеренно не включены; брать targets только из локального файла доступов.

## 1. Обследование — до любых изменений

SSH отдельно к обоим targets. Зафиксировать UTC timestamp, hostname, /etc/os-release, uptime, диск/RAM, root/sudo, публичные адреса, `ip -br addr`, `ip -4 route`, `ip -6 route`, `ip rule`, занятые порты, `sysctl net.ipv4.ip_forward`. Проверить ufw/nft/iptables, Docker version/info, действующие контейнеры, systemd units, wg show (без private keys). Структуру Docker сетей получать выборочно, не печатать env/ключи через raw inspect. Полный inspect сохранять в приватный backup.

На RU обнаружить контейнер по имени/образу/интерфейсам; стандарт amnezia-awg2 лишь кандидат. Внутри: ip -br addr, ip route, ip route get <EXIT>, iptables -t nat -S. Сопоставить Docker NetworkSettings с bridge на host. Не полагаться на eth0/eth1: порядок меняется после reboot. Исторический контейнер имел eth0/eth1 для 172.17.0.2 и172.29.172.2 с default via172.29.172.1; важны адрес/default route, а не имя интерфейса. Host bridge amn0, контейнер AWG10.8.1.0/24 NAT →172.29.172.2.

На новой системе подобрать непересекающийся туннельный /30 и свободную таблицу/марку/приоритеты. Не создавать конфликт с существующим wg-do. Существующую схему изучить и исправлять in place только после backup. `docker export` не включает volumes: проверить mounts и отдельно копировать хранилища конфигурации. /lib/modules не является пользовательской конфигурацией VPN.

Сначала проверить RU↔EXIT SSH/TCP, затем WG handshake/UDP. Обе стороны packet capture запускать одновременно с ограничением 30–60 секунд. Пустой tcpdump одного временного окна не доказывает DPI. Если существующее TCP живо, но новые SYN не доходят, не ломать рабочую сессию: проверить provider firewall, маршруты, локальные фильтры и сопоставить capture. Не бесконечно менять порты или серверы.

## 2. Установка Amnezia на новом RU

Если контейнер уже работает, использовать его. Не менять протокол/ключи/obfuscation для устранения DNS.

На чистом RU сначала проверить поддерживаемую ОС и требования официальной Amnezia. Предпочтительно установить через официальный AmneziaVPN client с автоматизацией интерфейса, если агент располагает ею. Ввод SSH-пароля выполнить без публичного вывода. SSH port и AWG UDP port — разные параметры. Приложение может запросить локальное подтверждение установки VPN: сообщить только этот неизбежный шаг.

Для headless установки изучить текущие официальные `client/server_scripts/awg/` и shared scripts репозитория amnezia-client, выбрать release/commit, скачать на диск, проверить содержимое и placeholders, затем выполнить проверенные файлы. Зафиксировать commit и хеши в state. Не исполнять curl|sh с изменяемой ветки и не выдумывать параметры AWG2. Соблюсти совместимость образа, модуля/утилиты awg, контейнерного старта, формата экспорта и клиента. Если невозможно проверить совместимость, остановить этот этап с точным объяснением; не обозначать собственный WireGuard профиль как импортируемый AmneziaWG.

Создать отдельный peer для каждого клиента и корректный экспорт, используя фактическую версию официального клиента/формат. Секреты не публиковать. Клиенту не отдавать admin backup вместо guest config. Root SSH нужен только для управления/установки, не для повседневного подключения.

## 3. WireGuard между серверами

Установить wireguard-tools официальным package manager. Генерировать приватные ключи локально на VPS под umask077 только если нужного ключа ещё нет; не менять их при повторном запуске. Конфиги0600. IPv4 forwarding EXIT сохранить в собственном sysctl.d файле.

Пример семантики конфигураций (адаптировать значения; не копировать ключи):

EXIT [Interface]: Address10.77.78.1/30, ListenPort51820, MTU1380. Peer RU publickey, AllowedIPs10.77.78.2/32. Endpoint RU необязателен, RU инициирует связь.

RU [Interface]: Address10.77.78.2/30, MTU1380, Table17778. Peer EXIT publickey, Endpoint EXIT:51820, AllowedIPs0.0.0.0/0, PersistentKeepalive25. Отдельная таблица ОБЯЗАТЕЛЬНА: default route RU не переключать через EXIT. rp_filter на wg-интерфейсе loose=2 при необходимости policy routing. Не ослаблять глобальные фильтры без доказанной причины.

На EXIT разрешить UDP выбранного порта от публичного RU в действующем firewall/provider firewall; FORWARD wg→публичный iface только source RU_tunnel/32 и reverse ESTABLISHED,RELATED; NAT MASQUERADE RU_tunnel/32 на публичный iface. Инструментально подтвердить фактический iface. PostUp добавляет правила через `-C ... || -I/-A ...`, PostDown удаляет только созданные правила (с комментариями/отдельной chain); обработать отсутствующее правило при down, не применять flush.

На RU:

```text
ip rule priority17778 from RU_tunnel/32 lookup17778
ip rule priority17771 fwmark0x1000000/0x1000000 lookup17778
table17778: default dev wg-do
table17778: unreachable default metric32760
```

Проверять полное selector/mask/table, а не только наличие номера приоритета. Если приоритет занят иным правилом — выбрать другой или согласовать миграцию, не удалять чужое. Source rule нужен DNS и curl --interface; в инциденте он исчез, хотя handshake был свежим и services active. Нужны и PostUp с проверкой отсутствия дубликата, и периодическое восстановление source rule. При конкуренции systemd timer/PostUp брать общий flock или повторно проверять правило после add-error. Все функции идемпотентны.

Проверить handshake + ping обоих tunnel IP; curl с RU обычный → RU public, curl --interface RU_tunnel → EXIT public. Один handshake не доказывает интернет-NAT.

## 4. DNS и выборочная маршрутизация

Установить dnsmasq-base/ipset/dnsutils, проверить compile options ipset. Не занимать systemd-resolved loopback53. Собственный dnsmasq port5353, listen127.0.0.1 и адрес hostbridge, bind-dynamic, no-resolv,no-hosts, domain-needed, cache-size1000, max-cache-ttl300,max-ttl300, filter-AAAA (ограничение IPv6, не полная защита).

Upstream DNS направлять с tunnel IP: `server=1.1.1.1@<RU_tunnel>` и `server=8.8.8.8@<RU_tunnel>`. До restart проверить существование source rule и работоспособность EXIT. Не считать увеличение dns-forward-max лечением отсутствующих ответов.

Обязательно `local=/resolver.arpa/`. Наблюдённый сбой: iPhone спрашивал SVCB _dns.resolver.arpa, получал внешний DDR и начинал попытки853/443; DNS сайтов исчезал из перехвата. После локального NXDOMAIN DNS приложений снова был виден. HTTPS? в tcpdump — тип DNS65, НЕ доказательство DoH. Отсутствие DNS в коротком capture может быть кешем. Не удалять сертификатные профили iPhone ради этой задачи.

Если есть доказательства обхода через HTTPS/SVCB ipv4hint, исследовать ответы `dig HTTPS` и выбранные IP. Только тогда рассмотреть точечную фильтрацию/совместимый resolver; не отключать все HTTPS RR без оснований. Авто-DDR fix не блокирует намеренный DoH приложений/Android Private DNS. Для таких клиентов явно проверить настройки либо предложить иной маршрут (например, отдельный профиль с полным выходом через EXIT) с объяснением изменения поведения.

Создать vpn_nl hash:ip familyinet timeout86400 до старта dnsmasq. DNS service должен запускаться после WG и сетей; Type=simple, dnsmasq --keep-in-foreground, ExecStartPre ipset create -exist и dnsmasq --test, Restart=on-failure. Не открывать рекурсивный DNS публичному интернету.

Списки для выбранных сервисов, включая поддомены (синтаксис `ipset=/domain/domain/vpn_nl`):

- ChatGPT: chatgpt.com, openai.com, oaistatic.com, oaiusercontent.com, oaistatsig.com, openaimerge.com.
- Claude: claude.ai, claude.com, anthropic.com, claudeusercontent.com.
- Gemini: gemini.google.com, aistudio.google.com, generativelanguage.googleapis.com, alkalimakersuite-pa.clients6.google.com; необходимые auth/CDN accounts.google.com,gstatic.com,googleusercontent.com.
- YouTube: youtube.com,youtu.be,youtube-nocookie.com,googlevideo.com,ytimg.com,youtubei.googleapis.com,youtube.googleapis.com,ggpht.com.
- Instagram: instagram.com,cdninstagram.com,fbcdn.net,facebook.net, **facebook.com**. В capture реально были gateway.facebook.com,edge-mqtt.facebook.com,graph.facebook.com,api.facebook.com и fallback.c10r.facebook.com. Это также направит часть Facebook через EXIT.
- Telegram: telegram.org,telegram.me,t.me,telegra.ph,telesco.pe,telegram-cdn.org + отдельный hash:net для официальных IPv4 сетей https://core.telegram.org/resources/cidr.txt. Загружать в temp, проверять непустоту и все CIDR, atomically swap set; при сетевой ошибке сохранять последнюю рабочую версию. Не обещать маршрут P2P-звонков только по этому списку.
- Общий auth при необходимости challenges.cloudflare.com; не маршрутизировать все CDN/AS Cloudflare/Google из-за одной неработающей страницы.

Динамические IP общего CDN могут направить посторонний сайт через EXIT. Это свойство IP-based split routing, явно указывать в отчёте. Не обещать точное разделение по приложению.

На host RU правила для обнаруженного bridge/source контейнера:

1. mangle PREROUTING: ingressbridge, sourcecontainer/32, dst vpn_nl → MARK --set-xmark0x1000000/0x1000000. Отдельно для telegram set. Не маркировать SSH/внешний AWG transport.
2. nat PREROUTING UDP/TCP dport53 от этого bridge/source → DNAT hostbridge:5353 (перед Docker LOCAL jump).
3. nat POSTROUTING sourcecontainer/32 выходwg-do → SNAT RU_tunnel (раньше общего DockerMASQUERADE).
4. DOCKER-USER accept sourcecontainer/32 bridge→wg; return ESTABLISHED,RELATED wg→bridge destinationcontainer/32. Если nft backend не имеет DOCKER-USER, не создавать фиктивную невызываемую цепочку: реализовать эквивалент в фактической forward pipeline.
5. Если INPUT policyDROP — явно разрешить DNS5353 только этому container/bridge и localhost. Снаружи не разрешать5353/53.

Контейнер уже NAT-ит клиентскую подсеть перед host; не применять host source10.8.1.0/24 вслепую. Если фактически нет container NAT, адаптировать схему к реальному источнику. Не менять чужие контейнеры.

## 5. Постоянство и безопасное применение

Перед редактированием timestamped backup каждого файла. Генерировать сначала в staging, проверять bash -n, dnsmasq --test, systemd-analyze verify; только затем atomic replace с правами. Проверка WireGuard не должна стартовать конфликтный интерфейс. Использовать `wg-quick strip` без вывода ключей, проверить структуру, затем настоящий контролируемый старт.

Managed /etc/amnezia-routing/, /usr/local/sbin/amnezia-routing-apply, amnezia-routing-dns.service, amnezia-routing-rules.service/timer. Допускается использовать существующие имена после проверки владельца/содержимого. Сервис rules Typeoneshot (inactive после успеха нормально), After/Wants network-online docker wg DNS. Timer OnBootSec30s OnUnitInactiveSec30s. Enable units и WG.

Apply script проверяет source rule и mark rule, unreachable default, sets, forward/NAT/DNS. Обнаруживает текущий контейнерный IP/bridge при запуске и проверяет их против expected network; при смене сети сначала подготовить новые узкие правила, затем удалить только собственные старые. Не допускать накопления дубликатов. Если контейнер временно отсутствует — логировать и повторить по timer, не открывать широкие разрешения.

Для сетевых изменений подготовить rollback script + ограниченный systemd rollback timer, восстанавливающий ТОЛЬКО управляемые файлы/правила. После независимого нового SSH соединения, проверки DNS/route отменить rollback. Не откатывать целиком iptables-save поверх живого Docker; сохранённые dumps служат справкой. Не считать reconnect старой сессии доказательством возможности нового SSH.

## 6. Проверка результата

Серверы: publicroutes неизменны, новые SSH обе стороны, WG recenthandshake и data, source rule/mark rule, table default+unreachable, DNSNXDOMAIN для _dns.resolver.arpa, A для выбранных сайтов, ipset membership полученных A, счётчики DNSDNAT и MARK, capture wg-do с выбранными назначениями. Не только ipify: обычный curl →RU; source-tunnelcurl →EXIT.

Клиент: подключение к RU, обычный ipify →RU, выбранный контрольный сайт действительно черезEXIT (capture/egressreport); ChatGPT отправляет сообщение, Instagram лента/видео/сообщения, Claude/Gemini/YouTube/Telegram по выбранному scope. iPhone проверить Wi-Fi/mobile, Android отдельно. На iPhone reboot очищал ранее обнаруженный DDR; DNS profile может отсутствовать. При существующем Android Private DNS объяснить возможный обход; не отключать без необходимости настройки на всех устройствах.

Не использовать постоянный ручной список единичных IP как окончательное решение. Временная ipset add timeout3600 допустима для диагностики, записать список. Перед финальной проверкой удалить только тестовые записи и restart dnsmasq cache; не flush всего ipset. Переподключить/перезапустить приложения для новых соединений: NAT старых conntrack flows может сохраняться. Не сбрасывать весь conntrack.

Указанные сайты могут запрещать datacenterIP; если без VPN сайт работает, предпочтительнее клиентское исключение для него, а не выключение всей схемы. Не считать любой403 неисправностью DNS.

При allow_reboot последовательно перезагрузить RU, восстановить SSH с ограниченным retry, проверить правила и клиентов; затем EXIT при необходимости. Никогда обе стороны одновременно. Проверить ipset repopulation после boot. Правило unreachable предотвращает fallback для УЖЕ помеченных пакетов, но не защищает новые назначения при пустом ipset. Отразить это ограничение, не называть схему абсолютным kill switch.

## 7. Backup и восстановление

RU: /etc/wireguard, /etc/amnezia-routing, managed script, все units/timers/drop-ins, необходимые sysctl файлы, полный docker inspect в приватный JSON, docker export контейнера + отдельно конфигурационные mounts/volumes (исключая /lib/modules). Для воспроизводимости при возможности docker image save; export сам по себе не сохраняет metadata ENTRYPOINT/ENV. Сохранить версии, образы/digests и сети. Предпочесть согласованную копию; live export не атомарен, на время не создавать peers. Если нужно остановить сервис для snapshot — учесть согласованный downtime.

EXIT: /etc/wireguard и управляемый sysctl/firewall/unit files. Сохранить безопасные диагностические rule/route/firewall dumps как reference. Архивы timestamped,0600. gzip -t, tar -tzf приватно, SHA256, скачать на компьютер, сравнить SHA256. Малый размер EXIT-архива допустим; хеш не доказывает полноту/восстанавливаемость. Отдельно клиентская admin backup Amnezia, не рассылать её гостевым устройствам.

Restore: проверить архив на абсолютные пути/.. и symlink escape перед распаковкой в staging; извлечь manifest, адаптировать публичные адреса/interface/nets. Не извлекать непроверенный tar прямо в /. Восстановить контейнер с проверенными metadata/network/mounts, ключами и правами. Повторить весь acceptance. Оригиналы не удалять до независимого подтверждения. Restore test только на отдельной среде либо в явно согласованном восстановлении; не ломать рабочий сервер ради теста.

## 8. Источники для перепроверки версии

- https://docs.amnezia.org/documentation/supported-linux-os-for-vps/
- https://docs.amnezia.org/documentation/instructions/backup-and-restore/
- https://github.com/amnezia-vpn/amnezia-client (актуальные awg scripts; не смешивать awg_legacy и awg)
- https://www.wireguard.com/quickstart/
- https://dnsmasq.org/docs/dnsmasq-man.html (ipset, server@source, local)
- https://www.rfc-editor.org/rfc/rfc9462.html#section-6.1 (DDR и forwarding)
- https://docs.docker.com/engine/network/firewall-iptables/
- https://core.telegram.org/resources/cidr.txt

Документ основан на фактически проверенной схеме пользователя и этих интерфейсах, не является гарантией неизменности всех версий.
