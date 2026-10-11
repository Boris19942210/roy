# ROY — Децентрализованная P2P-сеть

Учебный/исследовательский проект децентрализованной сети на Python.

## Возможности

- 🔐 Ed25519 подписи + Proof of Work для NodeID
- 🔒 ChaCha20Poly1305 шифрование сессий (X25519 ECDH)
- 🌐 Kademlia DHT (таблица маршрутизации, k-buckets)
- 🕳️ UDP Hole Punching через rendezvous-узлы
- 🔁 Relay-ретрансляция для симметричных NAT
- ⚙️ Адаптация к ресурсам устройства (CPU, батарея)
- 👥 Роли узлов: leaf / partial / relay / rendezvous / storage

## Установка

```bash
pip install -r requirements.txt
```

## Запуск

Bootstrap-узел (порт 4001):
```bash
python -m roy.node 4001
```

Второй узел (порт 4002):
```bash
python -m roy.node 4002
```

Сервер с подсчётом скорости:
```bash
python -m roy.server_node 4001
```

## Структура

| Файл | Назначение |
|------|-----------|
| `crypto.py` | Ключи, PoW, шифрование |
| `packet.py` | Формат пакетов протокола |
| `dht.py` | Kademlia DHT |
| `nat.py` | UDP hole punching |
| `relay.py` | Ретрансляция трафика |
| `adaptive.py` | Адаптация к ресурсам |
| `roles.py` | Роли узлов |
| `node.py` | Основной узел |
| `server_node.py` | Сервер со статистикой |

## Лицензия

MIT