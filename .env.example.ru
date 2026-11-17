# SmartNet Tracker - пример конфигурации.
# Скопируйте в `.env` рядом с бинарником (или запускайте из папки с этим файлом),
# трекер автоматически подхватит значения через `dotenvy`.
#
# Все переменные ниже - опциональные: без `.env` трекер стартует со значениями
# по умолчанию, показанными справа от `=`.

# --- Базовые параметры HTTP-сервера ---
# Порт, на котором слушает трекер (по умолчанию 7374).
SMARTNET_TRACKER_PORT=7374

# Путь к sled-базе (каталог создаётся автоматически).
SMARTNET_TRACKER_DB=./tracker-data

# TTL записи анонса в секундах: если провайдер не пришлёт heartbeat за это время,
# запись протухает и удаляется. По умолчанию 120.
SMARTNET_TRACKER_TTL=120

# Логировать каждый принятый/отклонённый анонс (полезно для отладки).
# Отключается значениями 0/false/off/no. По умолчанию ON.
SMARTNET_TRACKER_LOG_ANNOUNCE=1

# Экономика сидинга: on-chain проверка оплаты публикации + heartbeat-учёт K_up.
# ВЫКЛ (0/false/off/no) = аварийный режим, выдавать ВСЕ анонсы в /apps без проверки
# оплаты. По умолчанию ON.
ENABLE_INCENTIVIZED_SEEDING=1

# --- Официальный реестр (Official Repository) ---
# Пул REST-узлов SmartHoldem через запятую. Никогда не используйте один хардкод-узел
# в проде - трекер обходит список и берёт первый живой. По умолчанию - встроенный
# mainnet-пул (node0..node3.smartholdem.io + node0.sth.cx).
# SMARTHOLDEM_NODES=node0.smartholdem.io,node1.smartholdem.io

# Адрес-реестр доверенных разработчиков в блокчейне SmartHoldem.
OFFICIAL_DEVELOPERS=SdevsH3kMbcCFWnyYVtD2UYnBQQm66MxDn

# Адрес-реестр одобренных dApp (по appId).
OFFICIAL_DAPPS=SdAppjWaQf4v2JjuubvtwsKe3yuUCuq8i8

# Стартовый seed-список адресов разработчиков через запятую - fallback, если
# блокчейн недоступен на момент старта. Всегда дополняется адресом ORACLE-админа.
# DEVELOPERS=Saddress1,Saddress2

# --- Подпись ответов /seeders-dht (опционально) ---
# Секретный ключ оператора (secp256k1, hex, 32 байта). Если задан - GET /seeders-dht
# подписывается ECDSA, клиенты с закреплённым pubkey отклоняют подделки.
# Пустое значение = ответы не подписываются.
# OPERATOR_SECRET=

# --- Управление логированием ---
# Стандартный фильтр tracing-subscriber (например: smartnet_tracker=debug,tower_http=info).
# RUST_LOG=smartnet_tracker=info,tower_http=warn
