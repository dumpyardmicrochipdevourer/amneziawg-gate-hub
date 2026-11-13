# awg cascade

Ansible-плейбуки для VPN через две ноды: клиент подключается к российскому gate,
а зарубежный трафик выходит в интернет через зарубежный hub.

- 2 vps (gate,hub), ubuntu 24.04
- доступ к amnezia ppa; (у ru-gate также `ftp.ripe.net`).
- Открытые UDP-порты: **51820 и 51822 на RU**, **51821 на DE**.
- udp ports: 51820 && 51822 (gate) / 51821 (hub)
- python3 & ansible 2.16+ локально

## deploy

prepare-1-local
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp inventory/example.yml inventory/hosts.yml
```
(заполнить inventory/hosts.yml)

prepare-2-vps
```bash
ansible-playbook playbooks/hub.yml --tags prepare
ansible-playbook playbooks/gate.yml --tags prepare
```

Скопируй публичные ключи из вывода prepare в `awg_hub_link_public_key` и
`awg_gate_link_public_key` в inventory. Затем примени hub и gate:
```bash
ansible-playbook playbooks/hub.yml
ansible-playbook playbooks/gate.yml
```
(password auth => --ask-pass)

(clients-config => `/etc/amnezia/amneziawg/cascade-clients/`)

use-1 (change @RU_IP)
```bash
scp -i ~/.ssh/infra_key root@RU_IP:/etc/amnezia/amneziawg/cascade-clients/testcfg1.conf ./testcfg1.conf
chmod 600 testcfg1.conf
```

## ripe

По умолчанию IP-префиксы, зарегистрированные за RU в статистике **RIPE NCC**,
идут в интернет через российский gate. Остальной IPv4 — через немецкий hub.
Список обновляется ежедневно; при ошибке обновления сохраняется предыдущий.


## systemd-networkd

Правила `ip rule` и маршруты в таблицах 10010/10011 ставят хуки `awg-quick`.
По умолчанию `systemd-networkd` при перезапуске (например, needrestart после
unattended-upgrades) удаляет чужие правила и маршруты: туннель подключается,
но трафик клиентов отбрасывается. Поэтому роль кладёт на ноды
`/etc/systemd/networkd.conf.d/10-awg-cascade.conf` с
`ManageForeignRoutingPolicyRules=no` и `ManageForeignRoutes=no`.

Если правила уже пропали (`ip rule` без строк `10000` и `10010`), на gate:
```bash
systemctl restart awg-quick@awg1 && systemctl restart awg-quick@awg0
```

## client managment

```bash
cd /etc/amnezia/amneziawg
./add-client.sh name
./list-clients.sh
./remove-client.sh name
```

`add-client.sh` выбирает свободный октет, создаёт ключ и профиль в
`/etc/amnezia/amneziawg/cascade-clients/name.conf`.

если операция скрипта была прервана, следующий запуск (в том числе
`./list-clients.sh`) откатит её незавершённые изменения. 

После аварийного прерывания самого Ansible может остаться `.cascade-deploy`: убедись, что прогон больше не выполняется, затем на gate выполни
`rmdir /etc/amnezia/amneziawg/.cascade-deploy` и повтори команду.

