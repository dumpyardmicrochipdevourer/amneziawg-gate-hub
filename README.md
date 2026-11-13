# awg cascade

Ansible-плейбуки для VPN через несколько нод: клиент подключается к российскому gate,
а зарубежный трафик выходит в интернет через один из зарубежных hub.

## Схема

Один gate и N hub (N от 1 до 64). Каждый hub соединён с gate своим линком
(отдельный интерфейс, порт, сеть /30 и таблица маршрутизации). Каждый клиент
привязан к одному hub: его зарубежный трафик уходит только через него.
Российские адреса (список RIPE) идут напрямую через gate.

```
клиент ──awg0──▶ gate ──awg1─────▶ hub_de ──▶ интернет
                   │
                   └────awghub2──▶ hub_us ──▶ интернет
```

Если линк клиента остановлен, трафик клиента блокируется (unreachable), а не уходит
через чужой hub или напрямую.

## Требования

- gate и каждый hub: vps с ubuntu 24.04
- доступ к amnezia ppa (у ru-gate также `ftp.ripe.net`)
- python3 и ansible 2.16+ локально

## Порты (UDP)

| Нода | Порт | Назначение |
|---|---|---|
| gate | 51820 | клиенты |
| gate | 51822 + (N − 1) | линк с hub номер N: 51822, 51823, 51824, … |
| hub | 51821 | линк с gate |

Открой эти порты на соответствующих серверах.

## Переменные инвентаря

| Переменная | Где | Смысл |
|---|---|---|
| `awg_hub_index` | host vars hub | номер hub, 1..64, уникальный. Определяет интерфейс линка (`awg1` для 1, `awghubN` для N ≥ 2), порт, сеть и таблицу. Обязателен, если hub больше одного. Не меняй после развёртывания |
| `awg_hub_link_public_key` | host vars hub | публичный ключ линка этого hub (из вывода prepare). При одном hub глобальный ключ в `all.vars` по-прежнему работает; при двух и более hub ключи задаются только в host vars, у каждого свой (иначе ошибка `duplicate_key`) |
| `awg_gate_link_public_key` | all vars | публичный ключ линка gate |
| `awg_default_hub` | all vars | имя hub для клиентов без поля `hub`; по умолчанию hub с `awg_hub_index: 1` |
| `hub` | поле клиента в `awg_clients` | имя hub клиента (например `hub_us`); без поля — hub по умолчанию |

Предупреждение: клиенты реестра (созданные `add-client.sh` старой версией) не имеют
поля `hub` и считаются клиентами hub по умолчанию. При смене `awg_default_hub` они
переедут на новый hub. Сначала проверь `./list-clients.sh`, при необходимости
перенеси клиентов (см. ниже).

Пример: `inventory/example.yml`.

## Развёртывание

Подготовка локально:
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp inventory/example.yml inventory/hosts.yml
```
Заполни `inventory/hosts.yml` (адреса, `awg_hub_index` у каждого hub).

Подготовка серверов:
```bash
ansible-playbook playbooks/hub.yml --tags prepare
ansible-playbook playbooks/gate.yml --tags prepare
```

Скопируй публичные ключи из вывода prepare: ключ gate в `awg_gate_link_public_key`
(all vars), ключ каждого hub в `awg_hub_link_public_key` на этом hub. Затем примени
hub и gate:
```bash
ansible-playbook playbooks/hub.yml
ansible-playbook playbooks/gate.yml
```
(вход по паролю: `--ask-pass`)

Профили клиентов лежат в `/etc/amnezia/amneziawg/cascade-clients/`:
```bash
scp -i ~/.ssh/infra_key root@GATE_IP:/etc/amnezia/amneziawg/cascade-clients/testcfg1.conf ./testcfg1.conf
chmod 600 testcfg1.conf
```

Первый прогон `gate.yml` после обновления на версию с несколькими hub перезапускает
интерфейс `awg0` (меняется его хук): клиенты переподключатся. Линки к hub не
перезапускаются. Добавление нового hub тоже перезапускает только `awg0`.

## Обновление работающей установки

Первый прогон `gate.yml` новой версии перезапустит только `awg0` на несколько секунд.
Линк с hub и профили клиентов не меняются.

Перед прогоном проверь синтаксис и инвентарь (сервер при этом не меняется):
```bash
ansible-playbook playbooks/gate.yml --syntax-check
ansible-playbook playbooks/gate.yml --check --tags prepare
```

Если `awg0` не поднялся:
```bash
journalctl -u awg-quick@awg0 -n 50
/usr/local/sbin/awg-cascade-rules
```
Коды выхода `awg-cascade-rules`: 3 — проблема с файлами состояния (settings или
привязки), 4 — сбой команды `ip`.

Откат: верни прежний коммит репозитория и снова выполни `gate.yml`.

## systemd-networkd

Правила `ip rule` (приоритеты 10000, 10005, 10010) и маршруты в таблицах hub,
RU и заглушки ставят хуки `awg-quick` и `awg-cascade-rules`. По умолчанию
`systemd-networkd` при перезапуске (например, needrestart после
unattended-upgrades) удаляет чужие правила и маршруты: туннель подключается,
но трафик клиентов отбрасывается. Поэтому роль кладёт на ноды
`/etc/systemd/networkd.conf.d/10-awg-cascade.conf` с
`ManageForeignRoutingPolicyRules=no` и `ManageForeignRoutes=no`.

Если правила уже пропали (`ip rule` без строк `10000`, `10005` и `10010`),
на gate перезапусти сначала все линки (`awg1`, `awghubN`), затем `awg0`:
```bash
systemctl restart awg-quick@awg1 && systemctl restart awg-quick@awg0
```

## Добавить hub

Порядок для нового hub (пример `hub_us`):

1. Сначала подними сервер. Пока сервера нет, `hub_us` в инвентарь не вноси: прогон
   с недоступным hub не пройдёт.
2. Если до этого был один hub (`hub_de`), подготовь существующую схему:
   - добавь `hub_de` в host vars `awg_hub_index: 1`, иначе prepare для `hub_us`
     упадёт с ошибкой `index_required`;
   - перенеси публичный ключ `hub_de` из `awg_hub_link_public_key` в `all.vars`
     в host vars `hub_de` (и убери его из `all.vars`).
3. Добавь `hub_us` в группу `awg_hub` с `ansible_host` и новым уникальным
   `awg_hub_index`. В host vars `hub_us` обязательно задай свой
   `awg_hub_link_public_key: ''` (до prepare пустая строка), иначе он унаследует
   глобальный ключ и gate упадёт с `duplicate_key`.
4. Подготовь hub и получи его ключ:
   ```bash
   ansible-playbook playbooks/hub.yml --limit hub_us --tags prepare
   ```
5. Впиши ключ из вывода в `awg_hub_link_public_key` у `hub_us` в host vars.
6. Разверни hub, затем gate:
   ```bash
   ansible-playbook playbooks/hub.yml --limit hub_us
   ansible-playbook playbooks/gate.yml
   ```

Ошибки инвентаря (повтор индекса, дубль ключа, неизвестный hub у клиента и т. п.)
плейбук находит до изменений на серверах.

## Удалить hub

Автоматически hub не удаляется: прогон `gate.yml` с уменьшенным списком интерфейсов
завершится ошибкой. Вручную:

1. Переведи клиентов этого hub на другой hub (см. ниже).
   Если удаляется hub по умолчанию (с индексом 1 или заданный в `awg_default_hub`),
   сначала задай другой `awg_default_hub` и помни про клиентов реестра без поля `hub`:
   они переедут на новый hub по умолчанию.
2. На gate останови и выключи линк (`N` — номер hub, для hub с индексом 1 интерфейс `awg1`):
   ```bash
   systemctl disable --now awg-quick@awghubN
   rm /etc/amnezia/amneziawg/awghubN.conf
   rm /usr/local/sbin/awg-cascade-awghubN
   ```
3. Убери имя интерфейса из `/var/lib/awg-cascade/interfaces.json`.
4. Убери hub из инвентаря и выполни:
   ```bash
   ansible-playbook playbooks/gate.yml
   ```

После удаления в таблице маршрутизации удалённого hub до перезагрузки остаётся
маршрут unreachable; это безвредно.

## Клиенты

Клиенты, заданные в инвентаре (`awg_clients`), и клиенты скрипта (реестр на gate)
работают вместе.

Клиенты скрипта (на gate):
```bash
cd /etc/amnezia/amneziawg
./add-client.sh name                  # hub по умолчанию
./add-client.sh name --hub hub_us     # указанный hub
./list-clients.sh                     # колонка HUB показывает hub клиента
./remove-client.sh name
```

`add-client.sh` выбирает свободный октет, создаёт ключ и профиль в
`/etc/amnezia/amneziawg/cascade-clients/name.conf`.

Перенос клиента скрипта на другой hub = `remove` и `add --hub`:
```bash
./remove-client.sh name
./add-client.sh name --hub hub_us
```
Клиент получит новый ключ и новый профиль, возможно другой адрес: раздай профиль заново.

Клиент инвентаря: смени `hub` в `awg_clients` и повтори `gate.yml`. Перезапуск
интерфейсов не нужен, ключ и профиль не меняются.

Если операция скрипта была прервана, следующий запуск (в том числе
`./list-clients.sh`) откатит её незавершённые изменения.

Если `./list-clients.sh` не может восстановить прерванную операцию:
1. убедись, что ни один скрипт клиентов не выполняется;
2. удали журнал:
   ```bash
   rm /etc/amnezia/amneziawg/.cascade-client-transaction.json
   ```
3. выполни `ansible-playbook playbooks/gate.yml`: он пересоберёт конфиг, привязки и правила.

После аварийного прерывания самого Ansible может остаться `.cascade-deploy`: убедись,
что прогон больше не выполняется, затем на gate выполни
`rmdir /etc/amnezia/amneziawg/.cascade-deploy` и повтори команду.

## Проверка вручную

На gate (`10.2.0.2` — адрес клиента; таблицы hub: 10010, 10020, … с шагом 10):
```bash
ip rule show
ip route show table 10010
ip route get 1.1.1.1 from 10.2.0.2 iif awg0
ip route get 1.1.1.1 from 10.2.0.2 iif awg0 mark 0x64
```
Для зарубежного адреса маршрут идёт в линк hub клиента; с меткой `0x64`
(российский адрес) — через `eth0` gate.

Блокировка при остановке линка:
```bash
systemctl stop awg-quick@awg1
ip route get 1.1.1.1 from 10.2.0.2 iif awg0   # ожидается: RTNETLINK answers: Network is unreachable
systemctl start awg-quick@awg1
```

## ripe

По умолчанию IP-префиксы, зарегистрированные за RU в статистике **RIPE NCC**,
идут в интернет через российский gate. Остальной IPv4 — через hub клиента.
Список обновляется ежедневно; при ошибке обновления сохраняется предыдущий.

## Тесты

Локально, без Ansible:
```bash
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements-dev.txt
.venv\Scripts\python -m unittest discover tests
```
(Linux/macOS: `.venv/bin/python` вместо `.venv\Scripts\python`.) Без `jinja2` тесты
шаблонов падают с подсказкой установить `requirements-dev.txt`.

Необязательно: запуск в Docker на Linux (из корня репозитория):
```bash
docker run --rm -v "$PWD:/src:ro" python:3.12-slim sh -c 'cp -r /src /work && cd /work && pip install -q -r requirements-dev.txt && python -m unittest discover tests'
```
