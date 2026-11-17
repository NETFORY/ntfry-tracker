# SmartNet Tracker (`ntfry-tracker`)

A lightweight, standalone Rust (axum) **bootstrap directory** for WAN dApp
discovery. It lets SmartNet nodes find each other over the internet when LAN
mDNS is not enough.

The tracker is **stateless on disk**: it keeps only an in-memory registry of
*signed* app announcements with a TTL heartbeat. It **never stores blobs** -
the actual dApp content still moves peer-to-peer over `iroh-blobs`.

## Trust model

Every announced app is verified with the exact SmartHoldem crypto used by
the client. A spoofed announcement is rejected:

1. `id == base58check(0x3F ‖ ripemd160(secp256k1 compressed pubkey))`
2. The ECDSA signature over `sha256(id|name|description|merkle)` must verify
   against that public key.

## Build & run

```bash
cd tracker
cargo build --release
./target/release/ntfry-tracker
```

Defaults: binds `0.0.0.0:7374`, announcement TTL `120s`.

Override via env:

```bash
SMARTNET_TRACKER_PORT=7374 \
SMARTNET_TRACKER_TTL=120 \
SMARTNET_TRACKER_LOG_ANNOUNCE=1 \
  ./target/release/ntfry-tracker
```

- `SMARTNET_TRACKER_LOG_ANNOUNCE` - log new dApps (`NEW`) and new seeders (`+seed`) at `INFO`,
  rejected announces at `WARN`. Since **v1.9.2** routine `refresh` heartbeats are not logged per
  dApp; an `announce summary` line every 5 min shows heartbeats / nodes / refreshes instead.
  **On by default**; disable with `0` (also `false`/`off`/`no`).
  Stats counters in `/stats` keep counting even when logging is off.

The client ships these public seed trackers by default (configurable in
**Settings -> P2P -> WAN TRACKERS**):

## API

| Method | Path          | Purpose                                              |
| ------ | ------------- | ---------------------------------------------------- |
| GET    | `/`           | HTML status dashboard (auto-refreshes `/stats`) - open in a browser |
| POST   | `/announce`   | Heartbeat: register/refresh the apps a node serves   |
| GET    | `/apps`       | All known apps (deduped) with seed counts + providers|
| GET    | `/app/:id`    | Providers for a single app id                        |
| GET    | `/seeds`      | Distinct live nodes (endpoints) seen recently        |
| GET    | `/stats`      | Aggregate stats: live apps/providers/endpoints, lifetime accept/reject totals, top-10 apps by seeds |
| GET    | `/health`     | Liveness + registry stats                            |
| GET    | `/pqweb`      | PQ Web egress nodes (`{nodes:[{id,region}], ts, sig}`) - operator-curated via env `PQWEB_NODES`, ECDSA-signed with `OPERATOR_SECRET` (see below) |

### GET /pqweb (v1.6.6)

Signed list of `pq-web` nodes so NETFORY clients never paste EndpointIds by hand.

```bash
PQWEB_NODES="<EndpointId>@NL,<EndpointId>@FI" \
OPERATOR_SECRET=<hex secp256k1 secret> \
  ./target/release/ntfry-tracker
```

- entries are `<EndpointId>[@REGION]`, separated by commas/whitespace; `EndpointId` is the
  value printed by `pq-web id --key …` (64 hex or 52 z-base32 chars);
- `sig` = ECDSA compact hex over `sha256(["pqweb", ts, "<id>@<region>"…].join("\n"))`
  using the same operator key as `/seeders-dht`; empty when `OPERATOR_SECRET` is unset
  (clients accept the unsigned list only if no operator pubkey is pinned).

### POST /pqweb/announce (v1.6.7) - node self-registration

`pq-web` nodes register themselves (heartbeat every 60 s, `--tracker` / `PQ_WEB_TRACKERS`):

```json
{ "id": "<hex EndpointId>", "region": "NL", "ver": "0.2.1", "ports": [443],
  "addrs": ["146.103.108.25:7843"], "relay": "https://relay-fsn7.sth.cx/", "ts": 1780000000,
  "sig": "<hex ed25519 by the node's iroh key over 'pqweb-announce|<id>|<region>|<ver>|<ts>|<addrs,>|<relay>'>" }
```

`open: true` (v1.6.9, `pq-web serve --open`) marks a node that accepts any https host - clients in dVPN
"all sites via pq-web" mode use only such nodes. Canon v3 adds `|<open 0/1>`; v2/v1 are still accepted.

`ipv6: true` (v1.7.1, pq-web ≥ 0.4.0) marks a node whose outbound TCP to sites goes over IPv6
(`--ip-mode auto|prefer6|only6`, Happy Eyeballs). Canon **v4** adds `|<ipv6 0/1>` after `open`; v3/v2/v1
are still accepted when `ipv6` is false. Served in `GET /pqweb` -> "v6" badge in the client.
- v1.9.1: `mycelium: bool` - the node also relays NETFORY Mycelium mushroom circuits
  (`pq-web serve --mycelium`, pq-web ≥ 0.6.0). Signed in the **v5 canon** = v4 line + `|1`;
  announces with `mycelium:true` are accepted only with a v5 signature (older canons never carry
  the flag). Served in `GET /pqweb` - NETFORY clients ≥ 1.135.239 use such nodes as Mycelium bootstrap relays.

`addrs`/`relay` (v1.6.8) let clients dial the node **directly** (`EndpointAddr` with ip:port + relay) instead of
relying on DNS/pkarr discovery; the v1 canon without them is still accepted for pq-web 0.2.0.

- the signature is verified against `id` (the node's own public key) - nobody can announce
  someone else's node; `ts` must be within ±5 min; entries expire 3 min after the last heartbeat;
- trust policy: when `PQWEB_NODES` is **empty** registration is open (nodes are served with
  `verified:false`); when it is **set** it acts as an allowlist - announces from other ids get 403
  and listed nodes are served `verified:true` (their liveness/version comes from the heartbeat);
- `GET /pqweb` returns env entries first, then live nodes; each node has `verified`, `ver`, `lastSeen`.
  The list signature canon is unchanged, so 1.135.191 clients keep working.
- `/stats.pqwebNodes` and the dashboard card "PQ Web nodes" show the current count.

### POST /announce

```json
{
  "node": "S...",                 // announcing node's SmartHoldem address (info)
  "endpointId": "<iroh node id>", // how peers reach this provider
  "apps": [{
    "id": "S...",                 // == address(publicKey)
    "name": "App",
    "description": "...",
    "tags": ["demo"],
    "merkle": "<blake3 root>",
    "hash": "<iroh-blobs tar hash>",
    "signature": "<ecdsa compact hex>",
    "publicKey": "<secp256k1 compressed hex>"
  }]
}
```

Response: `{ "ok": true, "accepted": N, "rejected": M, "ttlSecs": 120 }`.

## Tests

```bash
cargo test                          # crypto verify unit tests
cargo run --example gen_announce          # print a VALID announce  -> accepted
cargo run --example gen_announce tamper   # mutated after signing    -> rejected
cargo run --example gen_announce badid    # id != pubkey address     -> rejected
```
