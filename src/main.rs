// Author: TechnoL0g
// Project: SmartNet Core
/*
 * SmartNet // lightweight P2P discovery tracker
 *
 *   A standalone Rust (axum) bootstrap directory for WAN dApp discovery.
 *   It does NOT store blobs — only an in-memory registry of signed app
 *   announcements with a TTL heartbeat. Peers announce which dApps they
 *   serve (and their iroh endpointId); other peers query the registry to
 *   discover providers they could not reach over LAN mDNS.
 *
 *   Trust model (identical to the SmartHoldem client):
 *     - app id  == base58check(0x3F ‖ ripemd160(secp256k1 compressed pubkey))
 *     - ECDSA signature over sha256(id|name|description|merkle) must verify
 *       against that pubkey. Spoofed announcements are rejected.
 *
 *   Endpoints:
 *     POST /announce   — heartbeat: register/refresh the apps a node serves
 *     GET  /apps       — all known apps (deduped) with seed counts + providers
 *     GET  /app/:id    — providers for a single app id
 *     GET  /seeds      — distinct live nodes (endpoints) seen recently
 *     GET  /health     — liveness + registry stats
 *
 *   Defaults: bind 0.0.0.0:7374, announcement TTL 120s (override via env
 *   SMARTNET_TRACKER_PORT / SMARTNET_TRACKER_TTL).
 */

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Html,
    routing::{get, post},
    Json, Router,
};
use ripemd::Ripemd160;
use secp256k1::ecdsa::Signature;
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tower_http::cors::{Any, CorsLayer};

const VERSION_BYTE: u8 = 0x3f; // SmartHoldem network pubKeyHash 63
const DEFAULT_PORT: u16 = 7374;
const DEFAULT_TTL_SECS: u64 = 120;

// ---- Anti-spam payment verification (Phase B) ----
/// Public SmartHoldem node REST base.
const STH_API: &str = "https://node0.smartholdem.io/api";
/// Global Sapps escrow node — publish payments (memo `sth:<app_id>`) land here.
const ESCROW_ADDRESS: &str = "SappsPqDQXCRvoi1V2Hs9xycQeT1ptJWV1";
/// Admin wallet allowed to broadcast price directives (sender).
const ORACLE_SENDER: &str = "SeZLuyhhYf2qxs4ArPJ71oEu3x8EsVw51C";
/// Config wallet the price directives are sent to (recipient).
const ORACLE_RECIPIENT: &str = "SeTQeEAsHnHU1Y9EBjkRVNPB3fmUvfFUrk";
/// Official Repository: on-chain registry of trusted developer addresses.
const OFFICIAL_DEVS_ADDR: &str = "SdevsH3kMbcCFWnyYVtD2UYnBQQm66MxDn";
/// Official Repository: on-chain registry of explicitly approved dApp ids.
const OFFICIAL_DAPPS_ADDR: &str = "SdAppjWaQf4v2JjuubvtwsKe3yuUCuq8i8";
/// Dynamic-pricing defaults — aligned with the live governance directive
/// `sth_oracle:price_mb=2:base=10`. Total = base + round(MB) * price_mb.
const DEFAULT_BASE_PRICE: u64 = 10; // whole STH
const DEFAULT_PRICE_PER_MB: u64 = 2; // whole STH per (rounded) MB
const MIB: u64 = 1_048_576;
const SMARTHOSHI: u64 = 100_000_000; // 1 STH = 1e8 smarthoshi
/// Store-search exposure override. `false` (default) = ONLY paid+seeded apps are
/// indexed in the public directory; unpaid apps stay reachable solely via a
/// direct `sth://<app_id>` deep link (GET /app/{id}). Flip to surface everything.
const SHOW_ALL_APPS: bool = false;

// ---- Per-app 5-day paid seeding window (Phase G — per-app payout model) ----
/// Оплаченный период сидинга одного события финансирования (публикация/обновление).
const SEEDING_WINDOW_SECS: u64 = 5 * 86_400; // 5 дней
/// Как долго храним funding-события для дедупликации txid (окно + запас).
const FUNDING_RETAIN_SECS: u64 = 30 * 86_400;
/// Сколько дней держим посуточные бакеты онлайна сидера по приложению.
const SEEDSTAT_KEEP_DAYS: usize = 8;

// ============================================================
//  Wire types
// ============================================================

/// One app a node claims to serve, as sent in a heartbeat.
#[derive(Debug, Deserialize, Clone)]
struct AppAnnounce {
    id: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    merkle: String,
    /// monotonic published version of the app this provider serves.
    #[serde(default)]
    version: u32,
    /// epoch-seconds string of the published copy's last update.
    #[serde(default)]
    updated: String,
    /// iroh-blobs collection / tar hash the provider serves for this app.
    #[serde(default)]
    hash: String,
    /// total payload size in bytes (drives dynamic publish/update pricing).
    #[serde(default)]
    size: u64,
    /// ECDSA (compact, hex) over sha256(id|name|description|merkle).
    signature: String,
    /// secp256k1 compressed public key (hex).
    #[serde(rename = "publicKey")]
    public_key: String,
    /// developer address (manifest owner) — Official Repository filter input.
    #[serde(default)]
    owner: String,
    /// iroh-hash логотипа dApp (PNG-блоб) — прозрачный проброс, НЕ в подписи.
    #[serde(default)]
    logo: String,
    /// iroh-hash DAPP Preview 440×180 (PNG/JPG-блоб) — прозрачный проброс.
    #[serde(default)]
    preview: String,
}

#[derive(Debug, Deserialize)]
struct AnnounceRequest {
    /// SmartHoldem address of the announcing node (informational).
    #[serde(default)]
    node: String,
    /// iroh endpoint id the node listens on (how peers reach it).
    #[serde(rename = "endpointId")]
    endpoint_id: String,
    /// public URL where this node's /metrics is reachable (Network Map).
    #[serde(rename = "metricsUrl", default)]
    metrics_url: String,
    apps: Vec<AppAnnounce>,
    /// A few (≤8) live Mainline DHT node addrs (ip:port) from the announcer's
    /// routing table — pooled by the tracker and served via GET /dht so censored
    /// peers (blocked from public routers/seeder, DHT=0) can still bootstrap off
    /// fresh, hard-to-blanket-block random DHT nodes. Anti-spam: capped + validated.
    #[serde(default)]
    dht: Vec<String>,
    /// This announcer's OWN public DHT bootstrap addr (ip:port) — set by SmartNet
    /// seeders running an open DHT server. Pooled + served via GET /seeders-dht so
    /// fresh clients auto-discover working seeders (no manual config needed).
    #[serde(rename = "seederDht", default)]
    seeder_dht: String,
}

#[derive(Debug, Serialize)]
struct AnnounceResponse {
    ok: bool,
    accepted: usize,
    rejected: usize,
    #[serde(rename = "ttlSecs")]
    ttl_secs: u64,
}

#[derive(Debug, Serialize, Clone)]
struct ProviderOut {
    #[serde(rename = "endpointId")]
    endpoint_id: String,
    node: String,
    hash: String,
    version: u32,
}

#[derive(Debug, Serialize, Clone)]
struct AppOut {
    id: String,
    name: String,
    description: String,
    tags: Vec<String>,
    merkle: String,
    version: u32,
    #[serde(default)]
    updated: String,
    seeds: usize,
    /// on-chain publish-payment confirmed (anti-spam). Unpaid apps are hidden
    /// from the public directory but still reachable via a direct deep link.
    paid: bool,
    /// accumulated seeding-boost tips (smarthoshi) sent to escrow as `sth_boost:<id>`.
    #[serde(rename = "boostPool")]
    boost_pool: u64,
    /// seeding priority: 100 (base for paid) + 1 per boosted STH. Seeders sort DESC.
    #[serde(rename = "priorityWeight")]
    priority_weight: u32,
    /// total payload weight in bytes (drives the republish-cost display).
    #[serde(rename = "sizeBytes")]
    size_bytes: u64,
    /// dynamic republish cost in whole STH (base + round(MB)·price_mb).
    cost: u64,
    /// unix-время первой оплаты (начало 5-дневного окна публикации).
    #[serde(rename = "paidTs")]
    paid_ts: u64,
    /// суммарный банк АКТИВНЫХ окон (funding) + буст, в STH — к раздаче сидерам.
    #[serde(rename = "bankSth")]
    bank_sth: u64,
    /// дневной пул приложения (bank / 5), STH — информативно.
    #[serde(rename = "dailyPoolSth")]
    daily_pool_sth: f64,
    /// секунд до конца самого позднего активного окна оплаченного сидинга (0 = истёк).
    #[serde(rename = "secondsRemaining")]
    seconds_remaining: u64,
    /// активные события финансирования (ts + сумма STH) для payout-сервера.
    funding: Vec<FundingOut>,
    providers: Vec<ProviderOut>,
    /// developer address (manifest owner), '' for legacy announces.
    owner: String,
    /// Official Repository: owner ∈ trusted developers OR id ∈ approved dApps.
    official: bool,
    /// iroh-hash логотипа dApp ('' скрывается из ответа).
    #[serde(skip_serializing_if = "String::is_empty")]
    logo: String,
    /// iroh-hash DAPP Preview 440×180 ('' скрывается из ответа).
    #[serde(skip_serializing_if = "String::is_empty")]
    preview: String,
}

/// Активное событие финансирования в выдаче API (для payout-сервера).
#[derive(Debug, Serialize, Clone)]
struct FundingOut {
    id: String,
    ts: u64,
    #[serde(rename = "amountSth")]
    amount_sth: u64,
    #[serde(rename = "amountSmarthoshi")]
    amount_smarthoshi: String,
    #[serde(rename = "endsAt")]
    ends_at: u64,
}

#[derive(Debug, Serialize)]
struct SeedOut {
    #[serde(rename = "endpointId")]
    endpoint_id: String,
    node: String,
    apps: usize,
    #[serde(rename = "lastSeen")]
    last_seen: u64,
}

#[derive(Debug, Serialize)]
struct Health {
    ok: bool,
    apps: usize,
    providers: usize,
    #[serde(rename = "ttlSecs")]
    ttl_secs: u64,
    uptime: u64,
}

// ============================================================
//  In-memory registry (TTL'd)
// ============================================================

#[derive(Clone, Serialize, Deserialize)]
struct Provider {
    endpoint_id: String,
    node: String,
    hash: String,
    /// app version this provider serves (for update propagation).
    #[serde(default)]
    version: u32,
    /// last heartbeat (unix secs) — persisted so providers survive restarts.
    #[serde(default)]
    last_seen: u64,
    /// runtime expiry; NOT persisted (recomputed on load from last_seen + ttl).
    #[serde(skip, default = "Instant::now")]
    expires: Instant,
}

#[derive(Clone, Serialize, Deserialize)]
struct AppRecord {
    id: String,
    name: String,
    description: String,
    tags: Vec<String>,
    merkle: String,
    /// highest version seen across providers (the latest published).
    #[serde(default)]
    version: u32,
    /// epoch-seconds string of the published copy's last update.
    #[serde(default)]
    updated: String,
    /// on-chain publish payment confirmed by the verification loop (Phase B).
    #[serde(default)]
    paid: bool,
    /// accumulated seeding boost (smarthoshi) from `sth_boost:<id>` txs (Phase D).
    #[serde(default)]
    boost_pool_sth: u64,
    /// total payload size in bytes (latest announced) — used for dynamic pricing.
    #[serde(default)]
    size_bytes: u64,
    /// dynamic republish cost in whole STH (base + round(MB)·price_mb), recomputed
    /// each verify pass against the current governance params.
    #[serde(default)]
    cost_sth: u64,
    /// computed seeding priority weight (100 base + 1/boosted-STH).
    #[serde(default)]
    priority_weight: u32,
    /// unix-время первой оплаты (paid_ts) — начало отсчёта первого 5-дневного окна.
    #[serde(default)]
    paid_ts: u64,
    /// события финансирования (публикация + платные обновления/reseeding).
    /// Каждое = отдельный банк на 5 дней; хранятся 30д для дедупа по txid.
    #[serde(default)]
    funding: Vec<FundingEvent>,
    /// keyed by endpoint_id so re-announces refresh, not duplicate
    providers: HashMap<String, Provider>,
    /// developer address (manifest owner) from the latest announce.
    #[serde(default)]
    owner: String,
    /// iroh-hash логотипа из последнего анонса ('' у легаси).
    #[serde(default)]
    logo: String,
    /// iroh-hash DAPP Preview из последнего анонса ('' у легаси).
    #[serde(default)]
    preview: String,
}

/// Одно событие финансирования приложения (транзакция `sth:<id>` на escrow).
/// Публикация и каждое платное обновление создают своё событие → свой банк на
/// 5 дней. Наложение окон безопасно: каждый банк делится строго на 5 дней.
#[derive(Clone, Serialize, Deserialize)]
struct FundingEvent {
    /// unix-время, когда трекер ВПЕРВЫЕ увидел эту транзакцию (окно считается отсюда).
    ts: u64,
    /// сумма банка события в smarthoshi.
    #[serde(rename = "amount")]
    amount_smarthoshi: u64,
    /// on-chain id транзакции — ключ дедупликации (одна tx = одно событие).
    #[serde(default)]
    txid: String,
}

struct Registry {
    apps: HashMap<String, AppRecord>,
}

/// One live seeder's contribution stats for the Network Map leaderboard.
/// Populated from POST /announce (metricsUrl) + periodic /metrics scrape.
#[derive(Clone)]
struct SeederEntry {
    endpoint_id: String,
    node: String,
    metrics_url: String,
    /// last announce heartbeat (unix secs).
    last_seen: u64,
    apps: usize,
    bytes_seeded: u64,
    gb_seeded: f64,
    uptime_secs: u64,
    /// disk budget (GB) this seeder advertises — summed for global capacity.
    storage_limit_gb: f64,
    /// Byte-Hours ranking score: gb_seeded × (uptime_secs / 3600).
    score: f64,
    online: bool,
    last_scraped: u64,
    /// This seeder's public DHT bootstrap addr (ip:port), advertised in /announce
    /// and served via GET /seeders-dht for client auto-discovery.
    dht_addr: String,
}

/// Lifetime counters (since process start).
#[derive(Default)]
struct Stats {
    announce_requests: AtomicU64,
    accepted: AtomicU64,
    rejected: AtomicU64,
}

#[derive(Clone)]
struct AppState {
    reg: Arc<Mutex<Registry>>,
    ttl: Duration,
    started: Instant,
    /// log every accepted/rejected announce (toggle via env at startup)
    log_announce: bool,
    stats: Arc<Stats>,
    /// sled DB — persists the app directory so it survives restarts.
    db: sled::Db,
    /// live seeders (Network Map): endpoint_id -> contribution metrics.
    seeders: Arc<Mutex<HashMap<String, SeederEntry>>>,
    /// owner-deleted apps: id -> deletion unix ts. Blocks re-announce + tells
    /// headless seeders to purge (via GET /deleted). Cleared after the TTL.
    tombstones: Arc<Mutex<HashMap<String, u64>>>,
    /// global monetization kill-switch. false ⇒ expose ALL apps in /apps
    /// regardless of on-chain payment (emergency mode, set at startup).
    incentivized: bool,
    /// Anti-censorship DHT bootstrap pool: ip:port -> last_seen unix. Fed by
    /// announces, served (freshest subset) via GET /dht. Capped to bound memory.
    dht_pool: Arc<Mutex<HashMap<String, u64>>>,
    /// Optional operator signing key (secp256k1). When set (env OPERATOR_SECRET),
    /// GET /seeders-dht responses are ECDSA-signed so clients with the matching
    /// pubkey can reject poisoned/MITM'd seeder lists.
    operator_sk: Option<SecretKey>,
}

/// Caps for the anti-censorship DHT pool (anti-spam / memory bound).
const DHT_POOL_MAX: usize = 256;
const DHT_ACCEPT_PER_ANNOUNCE: usize = 8;
const DHT_SERVE_MAX: usize = 32;
/// Drop pooled DHT nodes not re-announced within this window (stale → likely dead).
const DHT_POOL_TTL_SECS: u64 = 3600;

impl AppState {
    fn prune(&self) {
        let now = Instant::now();
        let mut reg = self.reg.lock().unwrap();
        let mut emptied: Vec<String> = Vec::new();
        for rec in reg.apps.values_mut() {
            rec.providers.retain(|_, p| p.expires > now);
        }
        reg.apps.retain(|id, r| {
            if r.providers.is_empty() {
                emptied.push(id.clone());
                false
            } else {
                true
            }
        });
        // drop emptied apps from persistent storage too
        for id in emptied {
            let _ = self.db.remove(id.as_bytes());
        }
        if !reg.apps.is_empty() {
            let _ = self.db.flush();
        }
    }

    /// Write a single app record to sled (best-effort).
    fn persist(&self, rec: &AppRecord) {
        if let Ok(bytes) = serde_json::to_vec(rec) {
            let _ = self.db.insert(rec.id.as_bytes(), bytes);
        }
    }
}

/// Load the persisted app directory from sled into memory. Providers are
/// restored with a fresh TTL grace window (expires = now + ttl) so a quick
/// tracker restart keeps the directory populated until heartbeats refresh it;
/// genuinely dead providers then prune out after the TTL.
fn load_registry(db: &sled::Db, ttl: Duration) -> Registry {
    let now = Instant::now();
    let mut apps: HashMap<String, AppRecord> = HashMap::new();
    for item in db.iter() {
        let Ok((_, v)) = item else { continue };
        let Ok(mut rec) = serde_json::from_slice::<AppRecord>(&v) else { continue };
        for p in rec.providers.values_mut() {
            p.expires = now + ttl;
        }
        if !rec.providers.is_empty() {
            apps.insert(rec.id.clone(), rec);
        }
    }
    Registry { apps }
}

// ============================================================
//  Crypto verification (mirrors the SmartHoldem client)
// ============================================================

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    let mut r = [0u8; 32];
    r.copy_from_slice(&h.finalize());
    r
}

/// Маркер reveal-payload приватного dApp в description анонса.
const PRIV_REVEAL_MARKER: &str = "§P1§";

fn address_from_pubkey(pk_comp: &[u8]) -> String {
    let mut rip = Ripemd160::new();
    rip.update(pk_comp);
    let hash = rip.finalize();
    let mut payload = Vec::with_capacity(21);
    payload.push(VERSION_BYTE);
    payload.extend_from_slice(&hash);
    bs58::encode(payload).with_check().into_string()
}

/// Validate a single announcement: the id must be the address derived from
/// the pubkey and the ECDSA signature must verify. Two canons are accepted:
///   v2 `id|name|description|merkle|owner` → Ok(true)  — owner is signature-backed;
///   v1 `id|name|description|merkle`       → Ok(false) — legacy announce, the
///     unsigned `owner` claim MUST be ignored (no Official badge by owner).
fn verify_announce(a: &AppAnnounce) -> Result<bool, &'static str> {
    let pk_bytes = hex::decode(a.public_key.trim()).map_err(|_| "bad-pubkey-hex")?;
    let pk = PublicKey::from_slice(&pk_bytes).map_err(|_| "bad-pubkey")?;
    if address_from_pubkey(&pk.serialize()) != a.id {
        return Err("id-mismatch");
    }
    let sig_bytes = hex::decode(a.signature.trim()).map_err(|_| "bad-sig-hex")?;
    let sig = Signature::from_compact(&sig_bytes).map_err(|_| "bad-sig")?;
    let secp = Secp256k1::verification_only();
    let check = |canon: String| -> bool {
        let digest = sha256(canon.as_bytes());
        Message::from_digest_slice(&digest)
            .map(|msg| secp.verify_ecdsa(&msg, &sig, &pk).is_ok())
            .unwrap_or(false)
    };
    if check(format!("{}|{}|{}|{}|{}", a.id, a.name, a.description, a.merkle, a.owner)) {
        return Ok(true);
    }
    if check(format!("{}|{}|{}|{}", a.id, a.name, a.description, a.merkle)) {
        return Ok(false);
    }
    // Приватный dApp: description несёт reveal-payload (маркер §P1§…), который
    // НЕ входит в подпись манифеста — канон подписан с ПУСТЫМ description.
    // Имя/merkle/owner остаются под подписью; сам payload защищён E2EE —
    // подмена ломает расшифровку у участников (fail-closed скрывает dApp).
    if a.description.starts_with(PRIV_REVEAL_MARKER) {
        if check(format!("{}|{}||{}|{}", a.id, a.name, a.merkle, a.owner)) {
            return Ok(true);
        }
        if check(format!("{}|{}||{}", a.id, a.name, a.merkle)) {
            return Ok(false);
        }
    }
    Err("sig-verify-failed")
}

// ============================================================
//  Owner-signed deletion (tombstones)
// ============================================================

/// How long a deleted app stays tombstoned: trackers refuse to re-announce it and
/// expose it in /deleted so headless seeders purge their copy. After this window
/// the record clears (the id could in theory be re-published).
const TOMBSTONE_TTL_SECS: u64 = 7 * 24 * 3600;
/// Anti-replay window for a delete request's signed timestamp (±1 day skew).
const DELETE_MAX_DRIFT: u64 = 86_400;

#[derive(Debug, Deserialize)]
struct DeleteRequest {
    id: String,
    #[serde(rename = "publicKey")]
    public_key: String,
    signature: String,
    ts: u64,
}

/// Verify an owner-signed deletion: the id MUST equal address(pubkey) (only the
/// owner can delete) and the ECDSA signature over sha256(id|delete|ts) must
/// verify, with `ts` recent to block replay.
fn verify_delete(d: &DeleteRequest) -> Result<(), &'static str> {
    let pk_bytes = hex::decode(d.public_key.trim()).map_err(|_| "bad-pubkey-hex")?;
    let pk = PublicKey::from_slice(&pk_bytes).map_err(|_| "bad-pubkey")?;
    if address_from_pubkey(&pk.serialize()) != d.id {
        return Err("id-mismatch");
    }
    let now = now_unix();
    if d.ts + DELETE_MAX_DRIFT < now || d.ts > now + DELETE_MAX_DRIFT {
        return Err("stale-timestamp");
    }
    let digest = sha256(format!("{}|delete|{}", d.id, d.ts).as_bytes());
    let sig_bytes = hex::decode(d.signature.trim()).map_err(|_| "bad-sig-hex")?;
    let sig = Signature::from_compact(&sig_bytes).map_err(|_| "bad-sig")?;
    let msg = Message::from_digest_slice(&digest).map_err(|_| "bad-digest")?;
    Secp256k1::verification_only()
        .verify_ecdsa(&msg, &sig, &pk)
        .map_err(|_| "sig-verify-failed")
}

/// Load persisted tombstones (`tomb:<id>` → unix ts), dropping expired ones.
fn load_tombstones(db: &sled::Db) -> HashMap<String, u64> {
    let now = now_unix();
    let mut out = HashMap::new();
    for item in db.scan_prefix(b"tomb:") {
        let Ok((k, v)) = item else { continue };
        let id = String::from_utf8_lossy(&k).trim_start_matches("tomb:").to_string();
        let ts: u64 = String::from_utf8_lossy(&v).trim().parse().unwrap_or(0);
        if ts + TOMBSTONE_TTL_SECS > now {
            out.insert(id, ts);
        } else {
            let _ = db.remove(&k);
        }
    }
    out
}

// ============================================================
//  Handlers
// ============================================================

// ============================================================
//  Official Repository — on-chain registries of trusted developers
//  and approved dApps (scanned on boot + every 24h; persisted in sled).
// ============================================================

static OFFICIAL: OnceLock<Mutex<(HashSet<String>, HashSet<String>)>> = OnceLock::new();

fn official_sets() -> &'static Mutex<(HashSet<String>, HashSet<String>)> {
    OFFICIAL.get_or_init(|| Mutex::new((HashSet::new(), HashSet::new())))
}

/// App is official when its manifest owner is a trusted developer OR the
/// appId itself was explicitly approved on-chain.
fn is_official(id: &str, owner: &str) -> bool {
    let g = official_sets().lock().unwrap();
    g.1.contains(id) || (!owner.is_empty() && g.0.contains(owner))
}

fn looks_like_sth_address(s: &str) -> bool {
    s.len() >= 26 && s.len() <= 40 && s.starts_with('S') && s.chars().all(|c| c.is_ascii_alphanumeric())
}

/// Scan one registry address over the node pool (SMARTHOLDEM_NODES env or the
/// default mainnet pool) — never a single hard-coded node.
fn official_scan_registry(recipient: &str) -> Result<Vec<String>, String> {
    let nodes: Vec<String> = std::env::var("SMARTHOLDEM_NODES")
        .ok()
        .map(|s| {
            s.split(',')
                .map(|x| x.trim().to_string())
                .filter(|x| !x.is_empty())
                .collect()
        })
        .filter(|v: &Vec<String>| !v.is_empty())
        .unwrap_or_else(|| {
            vec![
                "node0.smartholdem.io".into(),
                "node1.smartholdem.io".into(),
                "node2.smartholdem.io".into(),
                "node3.smartholdem.io".into(),
                "node0.sth.cx".into(),
            ]
        });
    let mut last_err = String::from("no nodes");
    'hosts: for host in nodes {
        // Пагинация: реестр может превышать 100 tx — идём до meta.pageCount
        // (cap 50 страниц). Ошибка любой страницы → следующий узел пула:
        // частичный результат опасен, снапшот реестра заменяется целиком.
        let mut out: Vec<String> = Vec::new();
        let mut page: u64 = 1;
        loop {
            let url = format!(
                "https://{}/api/transactions?recipientId={}&senderId={}&page={}&limit=100&orderBy=timestamp:desc",
                host, recipient, ORACLE_SENDER, page
            );
            let resp = match ureq::get(&url).timeout(Duration::from_secs(12)).call() {
                Ok(r) => r,
                Err(e) => {
                    last_err = e.to_string();
                    continue 'hosts;
                }
            };
            // ureq без feature "json": строка → serde_json
            let txt = match resp.into_string() {
                Ok(t) => t,
                Err(e) => {
                    last_err = e.to_string();
                    continue 'hosts;
                }
            };
            let v: serde_json::Value = match serde_json::from_str(&txt) {
                Ok(v) => v,
                Err(e) => {
                    last_err = e.to_string();
                    continue 'hosts;
                }
            };
            let arr = v.get("data").and_then(|d| d.as_array()).cloned().unwrap_or_default();
            for tx in &arr {
                if tx.get("sender").and_then(|s| s.as_str()) != Some(ORACLE_SENDER) {
                    continue;
                }
                let vf = tx
                    .get("vendorField")
                    .and_then(|s| s.as_str())
                    .unwrap_or("")
                    .trim()
                    .to_string();
                if looks_like_sth_address(&vf) && !out.contains(&vf) {
                    out.push(vf);
                }
            }
            let page_count =
                v.pointer("/meta/pageCount").and_then(|p| p.as_u64()).unwrap_or(page);
            if arr.is_empty() || page >= page_count || page >= 50 {
                return Ok(out);
            }
            page += 1;
        }
    }
    Err(last_err)
}

/// Env seed developers (DEVELOPERS=addr1,addr2) + the admin — blockchain-down fallback.
fn official_env_devs() -> HashSet<String> {
    let mut set: HashSet<String> = std::env::var("DEVELOPERS")
        .ok()
        .map(|s| {
            s.split(',')
                .map(|x| x.trim().to_string())
                .filter(|x| !x.is_empty())
                .collect()
        })
        .unwrap_or_default();
    set.insert(ORACLE_SENDER.to_string());
    set
}

/// Full refresh of both registries → in-memory sets + sled persistence.
fn official_refresh(state: &AppState) -> Result<(), String> {
    let devs_addr =
        std::env::var("OFFICIAL_DEVELOPERS").unwrap_or_else(|_| OFFICIAL_DEVS_ADDR.to_string());
    let dapps_addr =
        std::env::var("OFFICIAL_DAPPS").unwrap_or_else(|_| OFFICIAL_DAPPS_ADDR.to_string());
    let devs = official_scan_registry(&devs_addr)?;
    let dapps = official_scan_registry(&dapps_addr)?;
    let mut dev_set = official_env_devs();
    dev_set.extend(devs);
    let dapp_set: HashSet<String> = dapps.into_iter().collect();
    let _ = state
        .db
        .insert(b"official:devs", serde_json::to_vec(&dev_set).unwrap_or_default());
    let _ = state
        .db
        .insert(b"official:dapps", serde_json::to_vec(&dapp_set).unwrap_or_default());
    let _ = state.db.flush();
    tracing::info!(
        "official registry refreshed: {} developers, {} approved dapps",
        dev_set.len(),
        dapp_set.len()
    );
    *official_sets().lock().unwrap() = (dev_set, dapp_set);
    Ok(())
}

/// Hydrate the in-memory sets from sled at boot (before the first live scan).
fn official_load(state: &AppState) {
    let read = |k: &[u8]| -> HashSet<String> {
        state
            .db
            .get(k)
            .ok()
            .flatten()
            .and_then(|v| serde_json::from_slice(&v).ok())
            .unwrap_or_default()
    };
    let mut devs = read(b"official:devs");
    devs.extend(official_env_devs());
    let dapps = read(b"official:dapps");
    *official_sets().lock().unwrap() = (devs, dapps);
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ============================================================
//  Phase F — signed heartbeats + 24h sliding window + K_up
// ============================================================

const HB_SLOTS: u64 = 288; // 24h / 5min
const HB_SLOT_SECS: u64 = 300;
const HB_BYTES: usize = 36; // 288 bits
const HB_MAX_DRIFT: u64 = 60; // anti-replay clock skew (s)

/// Signed seeder availability heartbeat (POST /seeder/heartbeat).
#[derive(Debug, Deserialize)]
struct Heartbeat {
    timestamp: u64,
    #[serde(rename = "rewardAddress")]
    reward_address: String,
    #[serde(rename = "activeAppIds", default)]
    active_app_ids: Vec<String>,
    #[serde(rename = "publicKey")]
    public_key: String,
    signature: String,
    /// Self-reported disk budget (GB). Unsigned — informational, folded into the
    /// global capacity meter so home "client" nodes count, not just headless.
    #[serde(rename = "storageLimitGb", default)]
    storage_limit_gb: f64,
    /// Self-reported volume actually seeded (GB). Unsigned — folded into the
    /// global "seeded · 24h" usage meter for home nodes.
    #[serde(rename = "seededGb", default)]
    seeded_gb: f64,
    /// Self-reported accumulated torrent Byte-Hours (GiB·h). Unsigned — used as
    /// this home node's leaderboard score so it ranks alongside headless seeders
    /// (whose score = GB seeded × uptime hours). Same self-report trust model.
    #[serde(rename = "byteHours", default)]
    byte_hours: f64,
}

/// 24h rolling availability bitmask. bit 0 = most recent slot.
#[derive(Debug, Serialize, Deserialize)]
struct UptimeWindow {
    last_slot: u64,
    bits: Vec<u8>,
    #[serde(default)]
    active_apps: u32,
}

fn heartbeat_digest(hb: &Heartbeat) -> [u8; 32] {
    let mut ids = hb.active_app_ids.clone();
    ids.sort();
    sha256(
        format!(
            "sthb|{}|{}|{}",
            hb.reward_address,
            hb.timestamp,
            ids.join(",")
        )
        .as_bytes(),
    )
}

fn verify_heartbeat(hb: &Heartbeat) -> Result<(), &'static str> {
    let pk_bytes = hex::decode(hb.public_key.trim()).map_err(|_| "bad-pubkey-hex")?;
    let pk = PublicKey::from_slice(&pk_bytes).map_err(|_| "bad-pubkey")?;
    if address_from_pubkey(&pk.serialize()) != hb.reward_address {
        return Err("address-mismatch");
    }
    let digest = heartbeat_digest(hb);
    let sig_bytes = hex::decode(hb.signature.trim()).map_err(|_| "bad-sig-hex")?;
    let sig = Signature::from_compact(&sig_bytes).map_err(|_| "bad-sig")?;
    let msg = Message::from_digest_slice(&digest).map_err(|_| "bad-digest")?;
    Secp256k1::verification_only()
        .verify_ecdsa(&msg, &sig, &pk)
        .map_err(|_| "sig-verify-failed")
}

fn bits_set_count(bits: &[u8]) -> u32 {
    bits.iter().map(|b| b.count_ones()).sum()
}

fn set_bit0(bits: &mut [u8]) {
    if !bits.is_empty() {
        bits[0] |= 1;
    }
}

/// Shift the whole bitmask toward "older" by `delta` slots (bit i -> bit i+delta),
/// discarding bits that fall past HB_SLOTS. Newly exposed recent slots read 0.
fn shift_older(bits: &mut Vec<u8>, delta: u64) {
    if delta == 0 {
        return;
    }
    if delta as u64 >= HB_SLOTS {
        for b in bits.iter_mut() {
            *b = 0;
        }
        return;
    }
    let d = delta as usize;
    let mut out = vec![0u8; HB_BYTES];
    for i in 0..HB_SLOTS as usize {
        let src_byte = i / 8;
        let src_mask = 1u8 << (i % 8);
        if src_byte < bits.len() && bits[src_byte] & src_mask != 0 {
            let j = i + d;
            if j < HB_SLOTS as usize {
                out[j / 8] |= 1u8 << (j % 8);
            }
        }
    }
    *bits = out;
}

/// Non-linear uptime multiplier from the active-slot ratio. Incentivized OFF ⇒ 1.0.
fn compute_k_up(active_slots: u32, incentivized: bool) -> f64 {
    if !incentivized {
        return 1.0;
    }
    // Non-linear uptime penalty curve — MUST stay identical to the Layer-2 payout
    // server (payments-server/src/payout.js) so the in-app "Earn STH" estimate
    // matches what a node is actually paid:
    //   98–100% → 2.5 | 90–97.9% → 1.0 | 70–89.9% → 0.3 | <70% → 0.0 (evicted).
    let pct = (active_slots as f64) / (HB_SLOTS as f64) * 100.0;
    if pct >= 98.0 {
        2.5
    } else if pct >= 90.0 {
        1.0
    } else if pct >= 70.0 {
        0.3
    } else {
        0.0
    }
}

fn hb_key(addr: &str) -> Vec<u8> {
    [b"hb:", addr.as_bytes()].concat()
}

// ============================================================
//  Phase G — per-app-per-seeder seeding statistics
//
//  Из подписанных heartbeat'ов (active_app_ids) трекер ведёт по каждой паре
//  (app_id, reward_address) посуточные бакеты онлайна: сколько секунд адрес
//  реально сидировал это приложение в конкретный день. Это источник правды для
//  payout-сервера: дневной вес сидера = онлайн-секунды за день; правило «12ч
//  офлайна» считается от first_ts (первого дня раздачи), поэтому подключение в
//  середине периода корректно оплачивается. Аптайм подписан ключом адреса —
//  подделать чужой аптайм нельзя.
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct SeedStat {
    /// unix-время первого наблюдения раздачи этого приложения адресом.
    #[serde(rename = "firstTs", default)]
    first_ts: u64,
    /// последний heartbeat с этим приложением (для online-флага).
    #[serde(rename = "lastTs", default)]
    last_ts: u64,
    /// номер дня (unix/86400) → онлайн-секунды за день (≤86400). Храним ~8 дней.
    #[serde(default)]
    days: std::collections::BTreeMap<u64, u32>,
}

fn seedstat_key(app_id: &str, address: &str) -> Vec<u8> {
    format!("seedstat:{}:{}", app_id, address).into_bytes()
}

/// Зафиксировать один слот (HB_SLOT_SECS) онлайна раздачи приложения адресом.
fn record_seed_slot(db: &sled::Db, app_id: &str, address: &str, now: u64) {
    let key = seedstat_key(app_id, address);
    let mut st: SeedStat = db
        .get(&key)
        .ok()
        .flatten()
        .and_then(|v| serde_json::from_slice(&v).ok())
        .unwrap_or_default();
    if st.first_ts == 0 {
        st.first_ts = now;
    }
    st.last_ts = now;
    let day = now / 86_400;
    let e = st.days.entry(day).or_insert(0);
    *e = (*e + HB_SLOT_SECS as u32).min(86_400);
    // держим только последние SEEDSTAT_KEEP_DAYS дней
    while st.days.len() > SEEDSTAT_KEEP_DAYS {
        if let Some(&oldest) = st.days.keys().next() {
            st.days.remove(&oldest);
        } else {
            break;
        }
    }
    if let Ok(bytes) = serde_json::to_vec(&st) {
        let _ = db.insert(&key, bytes);
    }
}


async fn seeder_heartbeat(
    State(state): State<AppState>,
    Json(hb): Json<Heartbeat>,
) -> Result<StatusCode, (StatusCode, String)> {
    let now = now_unix();
    let drift = now.abs_diff(hb.timestamp);
    if drift > HB_MAX_DRIFT {
        return Err((StatusCode::BAD_REQUEST, "clock drift too large".into()));
    }
    if let Err(e) = verify_heartbeat(&hb) {
        return Err((StatusCode::UNAUTHORIZED, e.into()));
    }
    let current_slot = now / HB_SLOT_SECS;
    let key = hb_key(&hb.reward_address);
    let mut win: UptimeWindow = state
        .db
        .get(&key)
        .ok()
        .flatten()
        .and_then(|v| serde_json::from_slice(&v).ok())
        .unwrap_or(UptimeWindow {
            last_slot: current_slot,
            bits: vec![0u8; HB_BYTES],
            active_apps: 0,
        });
    if win.bits.len() != HB_BYTES {
        win.bits = vec![0u8; HB_BYTES];
    }
    if current_slot > win.last_slot {
        shift_older(&mut win.bits, current_slot - win.last_slot);
        win.last_slot = current_slot;
    }
    set_bit0(&mut win.bits);
    win.active_apps = hb.active_app_ids.len() as u32;
    if let Ok(bytes) = serde_json::to_vec(&win) {
        let _ = state.db.insert(&key, bytes);
        let _ = state.db.flush();
    }

    // Phase G: посуточная статистика раздачи по каждому активному приложению
    // (кап 200 id/heartbeat — анти-спам, хотя heartbeat уже подписан адресом).
    for app_id in hb.active_app_ids.iter().take(200) {
        let id = app_id.trim();
        if !id.is_empty() {
            record_seed_slot(&state.db, id, &hb.reward_address, now);
        }
    }
    let _ = state.db.flush();

    // Mirror this signed liveness beacon into the Network Map as a lightweight
    // CLIENT seeder (empty metricsUrl => the UI renders it as "Клиент" and the
    // /stats split counts it under clientSeeders). Home nodes expose no /metrics
    // endpoint, so GB stays 0; rank them by uptime hours, scaled tiny so the
    // GB-scored headless servers always sort above home nodes on the map.
    {
        let active_slots = bits_set_count(&win.bits) as u64;
        let uptime_secs = active_slots * HB_SLOT_SECS;
        let mut map = state.seeders.lock().unwrap();
        // Don't shadow a headless seeder that already advertises /metrics for the
        // same reward address — just refresh its liveness instead of adding a dup.
        let headless_key = map
            .iter()
            .find(|(_, e)| e.node == hb.reward_address && !e.metrics_url.trim().is_empty())
            .map(|(k, _)| k.clone());
        if let Some(k) = headless_key {
            if let Some(e) = map.get_mut(&k) {
                e.last_seen = now;
                e.online = true;
            }
        } else {
            let e = map
                .entry(hb.reward_address.clone())
                .or_insert_with(|| SeederEntry {
                    endpoint_id: hb.reward_address.clone(),
                    node: hb.reward_address.clone(),
                    metrics_url: String::new(),
                    last_seen: now,
                    apps: 0,
                    bytes_seeded: 0,
                    gb_seeded: 0.0,
                    uptime_secs: 0,
                    storage_limit_gb: 0.0,
                    score: 0.0,
                    online: true,
                    last_scraped: 0,
                    dht_addr: String::new(),
                });
            e.last_seen = now;
            e.online = true;
            e.apps = hb.active_app_ids.len();
            e.uptime_secs = uptime_secs;
            e.storage_limit_gb = hb.storage_limit_gb.max(0.0);
            e.gb_seeded = hb.seeded_gb.max(0.0);
            // Home nodes rank by the real torrent Byte-Hours (GiB·h) they report
            // in the heartbeat — so they compete on the public /map leaderboard
            // alongside headless seeders (score = GB × uptime hours). Absent that,
            // fall back to a tiny uptime score so they never outrank GB-backed servers.
            e.score = if hb.byte_hours > 0.0 {
                hb.byte_hours
            } else {
                uptime_secs as f64 / 3600.0 * 0.01
            };
        }
    }

    Ok(StatusCode::OK)
}

#[derive(Serialize)]
struct UptimeOut {
    address: String,
    #[serde(rename = "activeSlots")]
    active_slots: u32,
    slots: u64,
    #[serde(rename = "uptime24h")]
    uptime_24h: f64,
    #[serde(rename = "kUp")]
    k_up: f64,
    #[serde(rename = "activeApps")]
    active_apps: u32,
}

async fn seeder_uptime(
    State(state): State<AppState>,
    Path(address): Path<String>,
) -> Json<UptimeOut> {
    let now = now_unix();
    let current_slot = now / HB_SLOT_SECS;
    let mut active = 0u32;
    let mut active_apps = 0u32;
    if let Ok(Some(v)) = state.db.get(hb_key(&address)) {
        if let Ok(mut win) = serde_json::from_slice::<UptimeWindow>(&v) {
            if win.bits.len() == HB_BYTES {
                if current_slot > win.last_slot {
                    shift_older(&mut win.bits, current_slot - win.last_slot);
                }
                active = bits_set_count(&win.bits);
                active_apps = win.active_apps;
            }
        }
    }
    let ratio = (active as f64) / (HB_SLOTS as f64);
    Json(UptimeOut {
        address,
        active_slots: active,
        slots: HB_SLOTS,
        uptime_24h: (ratio * 1000.0).round() / 10.0, // percent, 1 decimal
        k_up: (compute_k_up(active, state.incentivized) * 100.0).round() / 100.0,
        active_apps,
    })
}


async fn announce(
    State(state): State<AppState>,
    Json(req): Json<AnnounceRequest>,
) -> Result<Json<AnnounceResponse>, (StatusCode, String)> {
    if req.endpoint_id.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "endpointId required".into()));
    }
    let expires = Instant::now() + state.ttl;
    let mut accepted = 0usize;
    let mut rejected = 0usize;

    // Snapshot of currently-tombstoned ids — owner-deleted apps must NOT be
    // re-created by other seeders' announces while the tombstone is live.
    let tombstoned: std::collections::HashSet<String> = {
        let now = now_unix();
        let mut t = state.tombstones.lock().unwrap();
        t.retain(|_, ts| *ts + TOMBSTONE_TTL_SECS > now);
        t.keys().cloned().collect()
    };

    {
        let mut reg = state.reg.lock().unwrap();
        let mut touched: Vec<String> = Vec::new();
        for a in &req.apps {
            if tombstoned.contains(&a.id) {
                rejected += 1;
                continue;
            }
            let owner_trusted = match verify_announce(a) {
                Ok(t) => t,
                Err(_) => {
                    rejected += 1;
                    if state.log_announce {
                        tracing::warn!(
                            "announce REJECTED app={} endpoint={} (bad signature/id)",
                            a.id,
                            req.endpoint_id
                        );
                    }
                    continue;
                }
            };
            // owner учитывается ТОЛЬКО когда покрыт подписью (canon v2) —
            // легаси-анонс с приписанным owner не даст бейдж Official
            let owner = if owner_trusted { a.owner.clone() } else { String::new() };
            let is_new_app = !reg.apps.contains_key(&a.id);
            let rec = reg.apps.entry(a.id.clone()).or_insert_with(|| AppRecord {
                id: a.id.clone(),
                name: a.name.clone(),
                description: a.description.clone(),
                tags: a.tags.clone(),
                merkle: a.merkle.clone(),
                version: a.version,
                updated: a.updated.clone(),
                paid: false,
                boost_pool_sth: 0,
                size_bytes: a.size,
                cost_sth: 0,
                priority_weight: 0,
                paid_ts: 0,
                funding: Vec::new(),
                providers: HashMap::new(),
                owner: owner.clone(),
                logo: a.logo.clone(),
                preview: a.preview.clone(),
            });
            // refresh metadata from the (verified) announcement
            if !a.name.is_empty() {
                rec.name = a.name.clone();
            }
            if !owner.is_empty() {
                rec.owner = owner.clone();
            }
            if !a.description.is_empty() {
                rec.description = a.description.clone();
            }
            if !a.tags.is_empty() {
                rec.tags = a.tags.clone();
            }
            rec.merkle = a.merkle.clone();
            if !a.updated.is_empty() {
                rec.updated = a.updated.clone();
            }
            // хэши медиа обновляются последним непустым анонсом (content-addressed)
            if !a.logo.is_empty() {
                rec.logo = a.logo.clone();
            }
            if !a.preview.is_empty() {
                rec.preview = a.preview.clone();
            }
            if a.size > 0 {
                rec.size_bytes = a.size;
            }
            if a.version > rec.version {
                rec.version = a.version;
            }
            let is_new_provider = !rec.providers.contains_key(&req.endpoint_id);
            rec.providers.insert(
                req.endpoint_id.clone(),
                Provider {
                    endpoint_id: req.endpoint_id.clone(),
                    node: req.node.clone(),
                    hash: a.hash.clone(),
                    version: a.version,
                    last_seen: now_unix(),
                    expires,
                },
            );
            accepted += 1;
            touched.push(a.id.clone());
            if state.log_announce {
                let kind = if is_new_app {
                    "NEW"
                } else if is_new_provider {
                    "+seed"
                } else {
                    "refresh"
                };
                tracing::info!(
                    "announce {} app={} name={:?} v{} node={} endpoint={} hash={}",
                    kind,
                    a.id,
                    rec.name,
                    a.version,
                    req.node,
                    req.endpoint_id,
                    a.hash
                );
            }
        }
        // persist the touched records so the directory survives restarts
        for id in touched {
            if let Some(rec) = reg.apps.get(&id) {
                state.persist(rec);
            }
        }
        let _ = state.db.flush();
    }

    state.stats.announce_requests.fetch_add(1, Ordering::Relaxed);
    state.stats.accepted.fetch_add(accepted as u64, Ordering::Relaxed);
    state.stats.rejected.fetch_add(rejected as u64, Ordering::Relaxed);

    // Anti-censorship DHT pool: accept a CAPPED, VALIDATED handful of the
    // announcer's live DHT nodes (ip:port). Prevents a single announce from
    // flooding the pool and rejects anything that isn't a real socket addr.
    if !req.dht.is_empty() {
        let now = now_unix();
        let mut pool = state.dht_pool.lock().unwrap();
        for raw in req.dht.iter().take(DHT_ACCEPT_PER_ANNOUNCE) {
            let n = raw.trim();
            if n.parse::<std::net::SocketAddr>().is_ok() {
                pool.insert(n.to_string(), now);
            }
        }
        // prune stale, then bound size by evicting the oldest entries
        pool.retain(|_, ts| *ts + DHT_POOL_TTL_SECS > now);
        if pool.len() > DHT_POOL_MAX {
            let mut by_age: Vec<(String, u64)> =
                pool.iter().map(|(k, v)| (k.clone(), *v)).collect();
            by_age.sort_by_key(|(_, ts)| *ts);
            for (k, _) in by_age.into_iter().take(pool.len() - DHT_POOL_MAX) {
                pool.remove(&k);
            }
        }
    }

    // Network Map: register/refresh the announcing seeder if it advertised a
    // public /metrics URL. Contribution stats are filled by the scrape task.
    if !req.metrics_url.trim().is_empty() {
        let mut s = state.seeders.lock().unwrap();
        let entry = s.entry(req.endpoint_id.clone()).or_insert_with(|| SeederEntry {
            endpoint_id: req.endpoint_id.clone(),
            node: req.node.clone(),
            metrics_url: req.metrics_url.trim().to_string(),
            last_seen: now_unix(),
            apps: accepted,
            bytes_seeded: 0,
            gb_seeded: 0.0,
            uptime_secs: 0,
            storage_limit_gb: 0.0,
            score: 0.0,
            online: false,
            last_scraped: 0,
            dht_addr: String::new(),
        });
        entry.node = req.node.clone();
        entry.metrics_url = req.metrics_url.trim().to_string();
        entry.last_seen = now_unix();
        entry.apps = accepted;
        // Record the seeder's advertised DHT bootstrap addr (validated) for /seeders-dht.
        let sd = req.seeder_dht.trim();
        if !sd.is_empty() && sd.parse::<std::net::SocketAddr>().is_ok() {
            entry.dht_addr = sd.to_string();
        }
    }

    Ok(Json(AnnounceResponse {
        ok: true,
        accepted,
        rejected,
        ttl_secs: state.ttl.as_secs(),
    }))
}

/// Auto-discovery: serve the DHT bootstrap addrs (ip:port) of SmartNet seeders
/// that announced an open DHT server recently — so fresh clients don't need to
/// add seeders manually (fully decentralized discovery). When an operator key is
/// configured the list is ECDSA-signed (clients with the pubkey reject forgeries).
#[derive(Serialize)]
struct SeedersDhtResp {
    seeders: Vec<String>,
    /// secp256k1 ECDSA (compact, hex) over sha256(seeders.join("\n")). Empty = unsigned.
    sig: String,
}

async fn seeders_dht(State(state): State<AppState>) -> Json<SeedersDhtResp> {
    let now = now_unix();
    const FRESH_SECS: u64 = 1800; // 30 min
    let mut out: Vec<String> = {
        let s = state.seeders.lock().unwrap();
        s.values()
            .filter(|e| !e.dht_addr.is_empty() && e.last_seen + FRESH_SECS > now)
            .map(|e| e.dht_addr.clone())
            .collect()
    };
    out.sort();
    out.dedup();
    let sig = match &state.operator_sk {
        Some(sk) => {
            let digest = sha256(out.join("\n").as_bytes());
            let msg = Message::from_digest_slice(&digest).unwrap();
            let s = Secp256k1::signing_only().sign_ecdsa(&msg, sk);
            hex::encode(s.serialize_compact())
        }
        None => String::new(),
    };
    Json(SeedersDhtResp { seeders: out, sig })
}

/// Anti-censorship bootstrap: serve the freshest subset of pooled DHT nodes
/// (ip:port) so a peer blocked from public routers/seeder can still join Mainline.
async fn dht_bootstrap(State(state): State<AppState>) -> Json<Vec<String>> {
    let now = now_unix();
    let mut pool = state.dht_pool.lock().unwrap();
    pool.retain(|_, ts| *ts + DHT_POOL_TTL_SECS > now);
    let mut by_age: Vec<(String, u64)> = pool.iter().map(|(k, v)| (k.clone(), *v)).collect();
    // freshest first
    by_age.sort_by(|a, b| b.1.cmp(&a.1));
    Json(by_age.into_iter().take(DHT_SERVE_MAX).map(|(k, _)| k).collect())
}

fn app_to_out(rec: &AppRecord) -> AppOut {
    let providers: Vec<ProviderOut> = rec
        .providers
        .values()
        .map(|p| ProviderOut {
            endpoint_id: p.endpoint_id.clone(),
            node: p.node.clone(),
            hash: p.hash.clone(),
            version: p.version,
        })
        .collect();
    // app-level version = highest version any live provider serves
    let version = rec.providers.values().map(|p| p.version).max().unwrap_or(rec.version);
    // Активные окна оплаченного сидинга (ts + 5д > now) → банк к раздаче.
    let now = now_unix();
    let mut bank_sth = 0u64;
    let mut ends_max = 0u64;
    let funding: Vec<FundingOut> = rec
        .funding
        .iter()
        .filter(|f| f.ts + SEEDING_WINDOW_SECS > now)
        .map(|f| {
            let ends_at = f.ts + SEEDING_WINDOW_SECS;
            let amount_sth = f.amount_smarthoshi / SMARTHOSHI;
            bank_sth = bank_sth.saturating_add(amount_sth);
            if ends_at > ends_max {
                ends_max = ends_at;
            }
            FundingOut { id: f.txid.clone(), ts: f.ts, amount_sth, amount_smarthoshi: f.amount_smarthoshi.to_string(), ends_at }
        })
        .collect();
    // Буст теперь входит в funding-события (sth_boost:<id>), поэтому банк = сумма
    // активных окон без отдельного добавления boost_pool.
    let seconds_remaining = ends_max.saturating_sub(now);
    let daily_pool_sth = (bank_sth as f64) / 5.0;
    AppOut {
        id: rec.id.clone(),
        name: rec.name.clone(),
        description: rec.description.clone(),
        tags: rec.tags.clone(),
        merkle: rec.merkle.clone(),
        version,
        updated: rec.updated.clone(),
        seeds: providers.len(),
        paid: rec.paid,
        boost_pool: rec.boost_pool_sth,
        priority_weight: rec.priority_weight,
        size_bytes: rec.size_bytes,
        cost: rec.cost_sth,
        paid_ts: rec.paid_ts,
        bank_sth,
        daily_pool_sth,
        seconds_remaining,
        funding,
        providers,
        owner: rec.owner.clone(),
        official: is_official(&rec.id, &rec.owner),
        logo: rec.logo.clone(),
        preview: rec.preview.clone(),
    }
}

async fn list_apps(State(state): State<AppState>) -> Json<Vec<AppOut>> {
    state.prune();
    let reg = state.reg.lock().unwrap();
    // Anti-spam exposure filter: only PAID apps with at least one live seeder are
    // indexed in the public directory. Emergency override: when incentivized
    // seeding is OFF (ENABLE_INCENTIVIZED_SEEDING=false), expose EVERY app so the
    // P2P network keeps serving even if the blockchain check is unavailable.
    let expose_all = SHOW_ALL_APPS || !state.incentivized;
    let mut out: Vec<AppOut> = reg
        .apps
        .values()
        .filter(|rec| expose_all || (rec.paid && !rec.providers.is_empty()))
        .map(app_to_out)
        .collect();
    // Highest seeding priority first, then by live seed count.
    out.sort_by(|a, b| {
        b.priority_weight
            .cmp(&a.priority_weight)
            .then(b.seeds.cmp(&a.seeds))
    });
    Json(out)
}

async fn get_app(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<AppOut>, StatusCode> {
    state.prune();
    let reg = state.reg.lock().unwrap();
    match reg.apps.get(&id) {
        Some(rec) => Ok(Json(app_to_out(rec))),
        None => Err(StatusCode::NOT_FOUND),
    }
}

/// Одна запись per-app статистики сидера для payout-сервера.
#[derive(Serialize)]
struct SeedStatOut {
    address: String,
    #[serde(rename = "firstTs")]
    first_ts: u64,
    #[serde(rename = "lastTs")]
    last_ts: u64,
    /// онлайн сейчас (последний heartbeat не старше 2 слотов).
    online: bool,
    /// номер дня (unix/86400) → онлайн-секунды за этот день.
    days: std::collections::BTreeMap<u64, u32>,
}

/// `GET /app/{id}/seeders` — посуточная статистика раздачи приложения по каждому
/// reward-адресу. Источник правды для per-app-выплат (payments-server).
async fn app_seeders(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Json<Vec<SeedStatOut>> {
    let now = now_unix();
    let prefix = format!("seedstat:{}:", id);
    let mut out: Vec<SeedStatOut> = Vec::new();
    for item in state.db.scan_prefix(prefix.as_bytes()) {
        let Ok((k, v)) = item else { continue };
        let key = String::from_utf8_lossy(&k);
        let address = key.rsplit(':').next().unwrap_or("").to_string();
        if address.is_empty() {
            continue;
        }
        let Ok(st) = serde_json::from_slice::<SeedStat>(&v) else { continue };
        out.push(SeedStatOut {
            address,
            first_ts: st.first_ts,
            last_ts: st.last_ts,
            online: now.saturating_sub(st.last_ts) < 2 * HB_SLOT_SECS,
            days: st.days,
        });
    }
    Json(out)
}


/// Owner-signed app deletion. Verifies id==address(pubkey) + ECDSA over
/// sha256(id|delete|ts), then removes the app from the directory and records a
/// tombstone so it stops being announced and headless seeders purge it.
async fn delete_app_handler(
    State(state): State<AppState>,
    Json(req): Json<DeleteRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if let Err(e) = verify_delete(&req) {
        return Err((StatusCode::UNAUTHORIZED, e.into()));
    }
    {
        let mut reg = state.reg.lock().unwrap();
        reg.apps.remove(&req.id);
    }
    let _ = state.db.remove(req.id.as_bytes());
    let now = now_unix();
    {
        let mut t = state.tombstones.lock().unwrap();
        t.insert(req.id.clone(), now);
    }
    let _ = state
        .db
        .insert(format!("tomb:{}", req.id).as_bytes(), now.to_string().as_bytes());
    let _ = state.db.flush();
    if state.log_announce {
        tracing::info!("DELETE app={} (owner-signed tombstone)", req.id);
    }
    Ok(Json(serde_json::json!({ "ok": true, "id": req.id })))
}

/// List currently-tombstoned (owner-deleted) app ids. Headless seeders poll this
/// to purge deleted apps from their blob store and stop seeding them.
async fn deleted_apps(State(state): State<AppState>) -> Json<Vec<String>> {
    let now = now_unix();
    let mut t = state.tombstones.lock().unwrap();
    t.retain(|_, ts| *ts + TOMBSTONE_TTL_SECS > now);
    Json(t.keys().cloned().collect())
}

async fn seeds(State(state): State<AppState>) -> Json<Vec<SeedOut>> {
    state.prune();
    let now = now_unix();
    let reg = state.reg.lock().unwrap();
    // collapse providers across all apps into distinct endpoints
    let mut by_endpoint: HashMap<String, (String, usize)> = HashMap::new();
    for rec in reg.apps.values() {
        for p in rec.providers.values() {
            let e = by_endpoint.entry(p.endpoint_id.clone()).or_insert((p.node.clone(), 0));
            e.1 += 1;
        }
    }
    let out: Vec<SeedOut> = by_endpoint
        .into_iter()
        .map(|(endpoint_id, (node, apps))| SeedOut {
            endpoint_id,
            node,
            apps,
            last_seen: now,
        })
        .collect();
    Json(out)
}

async fn health(State(state): State<AppState>) -> Json<Health> {
    state.prune();
    let reg = state.reg.lock().unwrap();
    let providers: usize = reg.apps.values().map(|r| r.providers.len()).sum();
    Json(Health {
        ok: true,
        apps: reg.apps.len(),
        providers,
        ttl_secs: state.ttl.as_secs(),
        uptime: state.started.elapsed().as_secs(),
    })
}

#[derive(Debug, Serialize)]
struct StatTotals {
    #[serde(rename = "announceRequests")]
    announce_requests: u64,
    accepted: u64,
    rejected: u64,
}

#[derive(Debug, Serialize)]
struct TopApp {
    id: String,
    name: String,
    version: u32,
    seeds: usize,
    /// оплачен ли активный период сидинга.
    paid: bool,
    /// банк к раздаче (cost+boost активных окон), STH.
    #[serde(rename = "bankSth")]
    bank_sth: u64,
    /// секунд до конца оплаченного сидинга (0 = не активен).
    #[serde(rename = "secondsRemaining")]
    seconds_remaining: u64,
}

#[derive(Debug, Serialize)]
struct StatsOut {
    ok: bool,
    #[serde(rename = "uptimeSecs")]
    uptime_secs: u64,
    #[serde(rename = "ttlSecs")]
    ttl_secs: u64,
    apps: usize,
    providers: usize,
    endpoints: usize,
    #[serde(rename = "logAnnounce")]
    log_announce: bool,
    totals: StatTotals,
    #[serde(rename = "topApps")]
    top_apps: Vec<TopApp>,
    /// Network-Map seeder split (deduped by reward node). Lets operators see how
    /// much of the network is held by dedicated servers vs home "client" nodes.
    #[serde(rename = "serverSeeders")]
    server_seeders: usize,
    #[serde(rename = "clientSeeders")]
    client_seeders: usize,
    #[serde(rename = "seedersOnline")]
    seeders_online: usize,
    /// Operator signing pubkey (secp256k1 compressed, hex). Empty when signing is
    /// off. Lets clients auto-pin (TOFU) the key for /seeders-dht verification —
    /// old trackers simply omit it and clients stay in unsigned mode.
    #[serde(default)]
    pubkey: String,
}

/// Operator signing pubkey (compressed hex) or "" when no key is configured.
fn operator_pubkey_hex(state: &AppState) -> String {
    match &state.operator_sk {
        Some(sk) => hex::encode(PublicKey::from_secret_key(&Secp256k1::new(), sk).serialize()),
        None => String::new(),
    }
}

/// Standalone endpoint so clients can fetch + pin the operator key without /stats.
async fn operator_pubkey(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({ "pubkey": operator_pubkey_hex(&state) }))
}

/// Self-contained status dashboard served at `GET /`. It fetches `/stats` with
/// JS and auto-refreshes, so the operator can open the tracker in a browser and
/// see "alive / N nodes online / top apps" without curl.
const STATUS_HTML: &str = r###"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>SmartNet Tracker</title>
<style>
  :root{--bg:#0d0f12;--panel:#15181d;--border:#262b32;--accent:#d9822b;--text:#c9d1d9;--dim:#6b7280;--ok:#4a9e7f;--danger:#cc4141;--gold:#e2b53e}
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--text);font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:14px;line-height:1.5}
  .wrap{max-width:880px;margin:0 auto;padding:40px 22px}
  h1{font-size:18px;letter-spacing:.16em;color:var(--accent);margin:0 0 4px;font-weight:800}
  .sub{color:var(--dim);font-size:12px;letter-spacing:.08em;margin-bottom:26px}
  .status{display:inline-flex;align-items:center;gap:8px;padding:5px 12px;border:1px solid var(--ok);border-radius:999px;color:var(--ok);font-size:12px;letter-spacing:.1em;margin-bottom:24px}
  .dot{width:8px;height:8px;border-radius:50%;background:var(--ok);box-shadow:0 0 8px var(--ok);animation:pulse 1.6s ease-in-out infinite}
  @keyframes pulse{0%,100%{opacity:1}50%{opacity:.35}}
  .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;margin-bottom:28px}
  .card{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:16px}
  .card .k{font-size:11px;letter-spacing:.1em;color:var(--dim);text-transform:uppercase}
  .card .v{font-size:24px;font-weight:700;margin-top:8px;color:var(--text)}
  .card .v.accent{color:var(--accent)}
  .sect{font-size:11px;letter-spacing:.12em;color:var(--dim);text-transform:uppercase;margin:24px 0 12px;border-top:1px solid var(--border);padding-top:18px}
  table{width:100%;border-collapse:collapse}
  th,td{text-align:left;padding:9px 10px;font-size:13px;border-bottom:1px solid var(--border)}
  th{color:var(--dim);font-size:11px;letter-spacing:.08em;text-transform:uppercase}
  td.id{color:var(--accent);font-size:12px;word-break:break-all}
  td.seeds{text-align:right;color:var(--ok);font-weight:700}
  .empty{color:var(--dim);padding:14px 0}
  .foot{margin-top:26px;color:var(--dim);font-size:11px;letter-spacing:.06em}
  .badge{display:inline-block;padding:2px 8px;border:1px solid var(--border);border-radius:999px;font-size:11px;color:var(--dim)}
  a{color:var(--accent)}
</style>
</head>
<body>
<div class="wrap">
  <h1>// SMARTNET TRACKER_</h1>
  <div class="sub">WAN dApp discovery directory &middot; in-memory &middot; signed announces</div>
  <div class="status"><span class="dot"></span><span id="status">CONNECTING&hellip;</span></div>

  <div class="grid">
    <div class="card"><div class="k">Nodes online</div><div class="v accent" id="endpoints">&mdash;</div></div>
    <div class="card"><div class="k">Apps</div><div class="v" id="apps">&mdash;</div></div>
    <div class="card"><div class="k">Providers</div><div class="v" id="providers">&mdash;</div></div>
    <div class="card"><div class="k">Uptime</div><div class="v" id="uptime">&mdash;</div></div>
  </div>

  <div class="grid">
    <div class="card"><div class="k">Announce requests</div><div class="v" id="req">&mdash;</div></div>
    <div class="card"><div class="k">Accepted</div><div class="v" id="acc">&mdash;</div></div>
    <div class="card"><div class="k">Rejected</div><div class="v" id="rej">&mdash;</div></div>
    <div class="card"><div class="k">TTL</div><div class="v" id="ttl">&mdash;</div></div>
  </div>

  <div class="sect">Top apps by seeds</div>
  <table>
    <thead><tr><th>App ID</th><th>Name</th><th>Ver</th><th style="text-align:center">Paid</th><th style="text-align:right">Bank</th><th style="text-align:right">Seed left</th><th style="text-align:right">Seeds</th></tr></thead>
    <tbody id="top"><tr><td class="empty" colspan="7">loading&hellip;</td></tr></tbody>
  </table>

  <div class="foot">
    auto-refresh 3s &middot; logging <span class="badge" id="log">?</span> &middot;
    <span id="updated">&mdash;</span> &middot; raw: <a href="/stats">/stats</a>
  </div>
</div>
<script>
function fmtUptime(s){var d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60);
  if(d>0)return d+'d '+h+'h';if(h>0)return h+'h '+m+'m';if(m>0)return m+'m';return s+'s';}
function fmtLeft(s){if(!s||s<=0)return '&mdash;';var d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60);
  if(d>0)return d+'d '+h+'h';if(h>0)return h+'h '+m+'m';return m+'m';}
function esc(t){var e=document.createElement('div');e.textContent=t==null?'':t;return e.innerHTML;}
async function tick(){
  try{
    var r=await fetch('/stats',{cache:'no-store'});var d=await r.json();
    document.getElementById('status').textContent='ALIVE';
    document.getElementById('endpoints').textContent=d.endpoints;
    document.getElementById('apps').textContent=d.apps;
    document.getElementById('providers').textContent=d.providers;
    document.getElementById('uptime').textContent=fmtUptime(d.uptimeSecs);
    document.getElementById('req').textContent=d.totals.announceRequests;
    document.getElementById('acc').textContent=d.totals.accepted;
    document.getElementById('rej').textContent=d.totals.rejected;
    document.getElementById('ttl').textContent=d.ttlSecs+'s';
    document.getElementById('log').textContent=d.logAnnounce?'ON':'OFF';
    var tb=document.getElementById('top');
    if(d.topApps&&d.topApps.length){
      tb.innerHTML=d.topApps.map(function(a){
        var paid=a.paid?'<span style="color:var(--ok);font-weight:700">PAID</span>':'<span style="color:var(--dim)">&mdash;</span>';
        var bank=(a.bankSth>0)?('<span style="color:var(--gold)">'+a.bankSth+' STH</span>'):'<span style="color:var(--dim)">&mdash;</span>';
        var left=fmtLeft(a.secondsRemaining||0);
        return '<tr><td class="id">'+esc(a.id)+'</td><td>'+(esc(a.name)||'<span style="color:var(--dim)">no name</span>')+'</td><td style="color:var(--dim)">v'+(a.version||1)+'</td><td style="text-align:center">'+paid+'</td><td style="text-align:right">'+bank+'</td><td style="text-align:right;color:var(--dim)">'+left+'</td><td class="seeds">'+a.seeds+'</td></tr>';}).join('');
    }else{tb.innerHTML='<tr><td class="empty" colspan="7">no apps announced yet</td></tr>';}
    document.getElementById('updated').textContent='updated '+new Date().toLocaleTimeString();
  }catch(e){document.getElementById('status').textContent='OFFLINE';}
}
tick();setInterval(tick,3000);
</script>
</body>
</html>"###;

async fn index() -> Html<&'static str> {
    Html(STATUS_HTML)
}


async fn stats(State(state): State<AppState>) -> Json<StatsOut> {
    state.prune();
    // Seeder split (deduped by reward node) — computed before locking the app
    // registry to keep a single, consistent lock order.
    let (server_seeders, client_seeders, seeders_online) = {
        let s = state.seeders.lock().unwrap();
        let deduped = deduped_seeders(&s);
        let mut srv = 0usize;
        let mut cli = 0usize;
        let mut online = 0usize;
        for e in &deduped {
            if e.online {
                online += 1;
            }
            if e.metrics_url.trim().is_empty() {
                cli += 1;
            } else {
                srv += 1;
            }
        }
        (srv, cli, online)
    };
    let reg = state.reg.lock().unwrap();
    let providers: usize = reg.apps.values().map(|r| r.providers.len()).sum();
    let mut endpoints = std::collections::HashSet::new();
    for r in reg.apps.values() {
        for p in r.providers.values() {
            endpoints.insert(p.endpoint_id.clone());
        }
    }
    let now_ts = now_unix();
    let mut top: Vec<TopApp> = reg
        .apps
        .values()
        .map(|r| {
            // банк активных окон (cost) + буст, и остаток самого позднего окна
            let mut bank = 0u64;
            let mut ends_max = 0u64;
            for f in r.funding.iter().filter(|f| f.ts + SEEDING_WINDOW_SECS > now_ts) {
                bank = bank.saturating_add(f.amount_smarthoshi / SMARTHOSHI);
                ends_max = ends_max.max(f.ts + SEEDING_WINDOW_SECS);
            }
            TopApp {
                id: r.id.clone(),
                name: r.name.clone(),
                version: r.providers.values().map(|p| p.version).max().unwrap_or(r.version),
                seeds: r.providers.len(),
                paid: r.paid,
                bank_sth: bank,
                seconds_remaining: ends_max.saturating_sub(now_ts),
            }
        })
        .collect();
    // сначала активный платный сидинг (по остатку), затем по числу сидов
    top.sort_by(|a, b| {
        b.seconds_remaining
            .cmp(&a.seconds_remaining)
            .then(b.seeds.cmp(&a.seeds))
    });
    top.truncate(10);
    Json(StatsOut {
        ok: true,
        uptime_secs: state.started.elapsed().as_secs(),
        ttl_secs: state.ttl.as_secs(),
        apps: reg.apps.len(),
        providers,
        endpoints: endpoints.len(),
        log_announce: state.log_announce,
        totals: StatTotals {
            announce_requests: state.stats.announce_requests.load(Ordering::Relaxed),
            accepted: state.stats.accepted.load(Ordering::Relaxed),
            rejected: state.stats.rejected.load(Ordering::Relaxed),
        },
        top_apps: top,
        server_seeders,
        client_seeders,
        seeders_online,
        pubkey: operator_pubkey_hex(&state),
    })
}

// ============================================================
//  Network Map — live seeder leaderboard (Byte-Hours ranking)
// ============================================================

/// JSON scraped from a seeder's /metrics endpoint.
#[derive(Debug, Deserialize, Default)]
struct ScrapedMetrics {
    #[serde(rename = "uptimeSecs", default)]
    uptime_secs: u64,
    #[serde(rename = "bytesSeeded", default)]
    bytes_seeded: u64,
    #[serde(rename = "gbSeeded", default)]
    gb_seeded: f64,
    #[serde(rename = "appsSeeded", default)]
    apps_seeded: usize,
    #[serde(rename = "storageLimitGb", default)]
    storage_limit_gb: f64,
}

#[derive(Debug, Serialize)]
struct SeederOut {
    #[serde(rename = "endpointId")]
    endpoint_id: String,
    node: String,
    #[serde(rename = "metricsUrl")]
    metrics_url: String,
    #[serde(rename = "appsSeeded")]
    apps_seeded: usize,
    #[serde(rename = "gbSeeded")]
    gb_seeded: f64,
    #[serde(rename = "uptimeSecs")]
    uptime_secs: u64,
    score: f64,
    online: bool,
    #[serde(rename = "lastSeen")]
    last_seen: u64,
}

/// Poll every known seeder's /metrics URL, refresh its contribution stats and
/// recompute the Byte-Hours score (GB seeded × uptime hours). Drops seeders we
/// haven't heard an announce from in over an hour.
async fn scrape_seeders(state: &AppState) {
    let targets: Vec<(String, String)> = {
        let s = state.seeders.lock().unwrap();
        s.values()
            .filter(|e| !e.metrics_url.trim().is_empty())
            .map(|e| (e.endpoint_id.clone(), e.metrics_url.clone()))
            .collect()
    };
    for (eid, url) in targets {
        let u = url.clone();
        let scraped = tokio::task::spawn_blocking(move || {
            ureq::get(&u)
                .timeout(Duration::from_secs(8))
                .call()
                .ok()
                .and_then(|r| r.into_string().ok())
                .and_then(|t| serde_json::from_str::<ScrapedMetrics>(&t).ok())
        })
        .await
        .ok()
        .flatten();
        let mut s = state.seeders.lock().unwrap();
        if let Some(e) = s.get_mut(&eid) {
            match scraped {
                Some(m) => {
                    e.bytes_seeded = m.bytes_seeded;
                    e.gb_seeded = if m.gb_seeded > 0.0 {
                        m.gb_seeded
                    } else {
                        m.bytes_seeded as f64 / 1e9
                    };
                    e.uptime_secs = m.uptime_secs;
                    if m.storage_limit_gb > 0.0 {
                        e.storage_limit_gb = m.storage_limit_gb;
                    }
                    if m.apps_seeded > 0 {
                        e.apps = m.apps_seeded;
                    }
                    e.score = e.gb_seeded * (m.uptime_secs as f64 / 3600.0);
                    e.online = true;
                    e.last_scraped = now_unix();
                }
                None => e.online = false,
            }
        }
    }
    let now = now_unix();
    state.seeders.lock().unwrap().retain(|_, e| {
        // Client home-nodes (no /metrics) are pruned fast — 2 heartbeat slots —
        // so the map only ever shows currently-live clients. Headless servers
        // keep the 1h grace window (the /metrics scrape refreshes them).
        let ttl = if e.metrics_url.trim().is_empty() {
            2 * HB_SLOT_SECS
        } else {
            3600
        };
        now.saturating_sub(e.last_seen) < ttl
    });
}

async fn seeders_list(State(state): State<AppState>) -> Json<Vec<SeederOut>> {
    let s = state.seeders.lock().unwrap();
    // Collapse by reward node address (fall back to endpointId) so a seeder
    // that restarted with a fresh ephemeral endpointId isn't shown twice.
    // Prefer the online entry, then higher score, then the most recent.
    let mut by_key: HashMap<String, SeederEntry> = HashMap::new();
    for e in s.values() {
        let key = if e.node.trim().is_empty() {
            e.endpoint_id.clone()
        } else {
            e.node.trim().to_string()
        };
        let better = match by_key.get(&key) {
            None => true,
            Some(x) => {
                if e.online != x.online {
                    e.online
                } else if e.score != x.score {
                    e.score > x.score
                } else {
                    e.last_seen > x.last_seen
                }
            }
        };
        if better {
            by_key.insert(key, e.clone());
        }
    }
    let mut out: Vec<SeederOut> = by_key
        .into_values()
        .map(|e| SeederOut {
            endpoint_id: e.endpoint_id.clone(),
            node: e.node.clone(),
            metrics_url: e.metrics_url.clone(),
            apps_seeded: e.apps,
            gb_seeded: e.gb_seeded,
            uptime_secs: e.uptime_secs,
            score: e.score,
            online: e.online,
            last_seen: e.last_seen,
        })
        .collect();
    out.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
    Json(out)
}

/// Collapse the live seeder map by reward node (fall back to endpointId) so a
/// seeder that restarted with a fresh ephemeral endpointId isn't counted twice.
/// Prefers the online entry, then higher score, then the most recent.
fn deduped_seeders(seeders: &HashMap<String, SeederEntry>) -> Vec<SeederEntry> {
    let mut by_key: HashMap<String, SeederEntry> = HashMap::new();
    for e in seeders.values() {
        let key = if e.node.trim().is_empty() {
            e.endpoint_id.clone()
        } else {
            e.node.trim().to_string()
        };
        let better = match by_key.get(&key) {
            None => true,
            Some(x) => {
                if e.online != x.online {
                    e.online
                } else if e.score != x.score {
                    e.score > x.score
                } else {
                    e.last_seen > x.last_seen
                }
            }
        };
        if better {
            by_key.insert(key, e.clone());
        }
    }
    by_key.into_values().collect()
}

/// Aggregate global mesh storage capacity / usage across all UNIQUE seeders.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct NetworkStorageStats {
    /// sum of every seeder's advertised disk budget (GB).
    total_capacity_gb: f64,
    /// sum of bytes actually seeded across the mesh (GB).
    total_used_gb: f64,
    /// remaining reservable capacity (GB), clamped at 0.
    total_free_gb: f64,
    /// number of unique seeders currently online.
    online_nodes: usize,
    /// total unique seeders known (online or recently seen).
    total_nodes: usize,
    /// rolling ~24h history of total seeded GB (oldest→newest) for the dashboard sparkline.
    history: Vec<NetPoint>,
}

/// One point on the global network seeded-GB time-series.
#[derive(Serialize, Deserialize, Clone)]
struct NetPoint {
    t: u64,
    #[serde(rename = "usedGb")]
    used_gb: f64,
}

const NET_HIST_KEY: &[u8] = b"cfg:net_history";
const NET_HIST_MAX: usize = 48; // ~24h at one point / 30 min

fn read_net_history(db: &sled::Db) -> Vec<NetPoint> {
    db.get(NET_HIST_KEY)
        .ok()
        .flatten()
        .and_then(|v| serde_json::from_slice::<Vec<NetPoint>>(&v).ok())
        .unwrap_or_default()
}

/// Append a global seeded-GB snapshot (throttled to ~30 min) and trim to 24h.
fn record_network_history(state: &AppState) {
    let used = {
        let s = state.seeders.lock().unwrap();
        deduped_seeders(&s)
            .iter()
            .map(|e| e.gb_seeded.max(0.0))
            .sum::<f64>()
    };
    let now = now_unix();
    let mut hist = read_net_history(&state.db);
    if let Some(last) = hist.last() {
        if now.saturating_sub(last.t) < 1_500 {
            return; // < ~25 min since last point — skip
        }
    }
    hist.push(NetPoint { t: now, used_gb: round2(used) });
    if hist.len() > NET_HIST_MAX {
        let cut = hist.len() - NET_HIST_MAX;
        hist.drain(0..cut);
    }
    if let Ok(b) = serde_json::to_vec(&hist) {
        let _ = state.db.insert(NET_HIST_KEY, b);
        let _ = state.db.flush();
    }
}

fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

/// `GET /network/storage` — global cloud capacity meter for the dashboard.
async fn network_storage(State(state): State<AppState>) -> Json<NetworkStorageStats> {
    let nodes = {
        let s = state.seeders.lock().unwrap();
        deduped_seeders(&s)
    };
    let mut capacity = 0.0f64;
    let mut used = 0.0f64;
    let mut online = 0usize;
    for e in &nodes {
        capacity += e.storage_limit_gb.max(0.0);
        used += e.gb_seeded.max(0.0);
        if e.online {
            online += 1;
        }
    }
    let free = (capacity - used).max(0.0);
    let history = read_net_history(&state.db);
    Json(NetworkStorageStats {
        total_capacity_gb: round2(capacity),
        total_used_gb: round2(used),
        total_free_gb: round2(free),
        online_nodes: online,
        total_nodes: nodes.len(),
        history,
    })
}


/// Public, self-contained Network Map dashboard served at `GET /map`. Fetches
/// `/seeders` with JS and auto-refreshes — a leaderboard ranking every seeder
/// by their Byte-Hours contribution to incentivise hosting SmartNet dApps.
const MAP_HTML: &str = r###"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>SmartNet Network Map</title>
<style>
  :root{--bg:#0d0f12;--panel:#15181d;--border:#262b32;--accent:#d9822b;--text:#c9d1d9;--dim:#6b7280;--ok:#4a9e7f;--danger:#cc4141;--gold:#e2b53e}
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--text);font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:14px;line-height:1.5}
  .wrap{max-width:1000px;margin:0 auto;padding:40px 22px}
  h1{font-size:18px;letter-spacing:.16em;color:var(--accent);margin:0 0 4px;font-weight:800}
  .sub{color:var(--dim);font-size:12px;letter-spacing:.08em;margin-bottom:26px}
  .status{display:inline-flex;align-items:center;gap:8px;padding:5px 12px;border:1px solid var(--ok);border-radius:999px;color:var(--ok);font-size:12px;letter-spacing:.1em;margin-bottom:24px}
  .dot{width:8px;height:8px;border-radius:50%;background:var(--ok);box-shadow:0 0 8px var(--ok);animation:pulse 1.6s ease-in-out infinite}
  @keyframes pulse{0%,100%{opacity:1}50%{opacity:.35}}
  .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:14px;margin-bottom:28px}
  .card{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:16px}
  .card .k{font-size:11px;letter-spacing:.1em;color:var(--dim);text-transform:uppercase}
  .card .v{font-size:24px;font-weight:700;margin-top:8px;color:var(--text)}
  .card .v.accent{color:var(--accent)}
  .sect{font-size:11px;letter-spacing:.12em;color:var(--dim);text-transform:uppercase;margin:24px 0 12px;border-top:1px solid var(--border);padding-top:18px}
  table{width:100%;border-collapse:collapse}
  th,td{text-align:left;padding:10px;font-size:13px;border-bottom:1px solid var(--border)}
  th{color:var(--dim);font-size:11px;letter-spacing:.08em;text-transform:uppercase}
  td.rank{color:var(--dim);font-weight:700;width:38px}
  td.rank.top{color:var(--gold)}
  td.node{color:var(--accent);font-size:12px;word-break:break-all}
  td.num{text-align:right;font-variant-numeric:tabular-nums}
  td.score{text-align:right;color:var(--ok);font-weight:700}
  .badge{display:inline-block;width:8px;height:8px;border-radius:50%}
  .on{background:var(--ok);box-shadow:0 0 6px var(--ok)}
  .off{background:var(--danger)}
  .empty{color:var(--dim);padding:14px 0}
  .foot{margin-top:26px;color:var(--dim);font-size:11px;letter-spacing:.06em}
  a{color:var(--accent)}
</style>
</head>
<body>
<div class="wrap">
  <h1>// SMARTNET NETWORK MAP_</h1>
  <div class="sub">public seeder leaderboard &middot; ranked by Byte-Hours (GB seeded &times; uptime)</div>
  <div class="status"><span class="dot"></span><span id="status">CONNECTING&hellip;</span></div>

  <div class="grid">
    <div class="card"><div class="k">Seeders</div><div class="v accent" id="count">&mdash;</div></div>
    <div class="card"><div class="k">Online</div><div class="v" id="online">&mdash;</div></div>
    <div class="card"><div class="k">Total seeded</div><div class="v" id="gb">&mdash;</div></div>
    <div class="card"><div class="k">Apps covered</div><div class="v" id="apps">&mdash;</div></div>
  </div>

  <div class="sect">Leaderboard</div>
  <table>
    <thead><tr><th>#</th><th></th><th>Node / reward</th><th style="text-align:right">Apps</th><th style="text-align:right">GB</th><th style="text-align:right">Uptime</th><th style="text-align:right">GB&middot;h</th></tr></thead>
    <tbody id="rows"><tr><td class="empty" colspan="7">loading&hellip;</td></tr></tbody>
  </table>

  <div class="foot">auto-refresh 5s &middot; <span id="updated">&mdash;</span> &middot; raw: <a href="/seeders">/seeders</a></div>
</div>
<script>
function fmtUp(s){var d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60);
  if(d>0)return d+'d '+h+'h';if(h>0)return h+'h '+m+'m';if(m>0)return m+'m';return s+'s';}
function esc(t){var e=document.createElement('div');e.textContent=t==null?'':t;return e.innerHTML;}
async function tick(){
  try{
    var r=await fetch('/seeders',{cache:'no-store'});var d=await r.json();
    document.getElementById('status').textContent='ALIVE';
    document.getElementById('count').textContent=d.length;
    document.getElementById('online').textContent=d.filter(function(s){return s.online}).length;
    document.getElementById('gb').textContent=d.reduce(function(a,s){return a+(s.gbSeeded||0)},0).toFixed(2)+' GB';
    var maxApps=d.reduce(function(a,s){return Math.max(a,s.appsSeeded||0)},0);
    document.getElementById('apps').textContent=maxApps;
    var tb=document.getElementById('rows');
    if(d.length){
      tb.innerHTML=d.map(function(s,i){return '<tr><td class="rank'+(i<3?' top':'')+'">'+(i+1)+'</td>'+
        '<td><span class="badge '+(s.online?'on':'off')+'"></span></td>'+
        '<td class="node">'+esc(s.node||s.endpointId)+'</td>'+
        '<td class="num">'+(s.appsSeeded||0)+'</td>'+
        '<td class="num">'+(s.gbSeeded||0).toFixed(3)+'</td>'+
        '<td class="num">'+fmtUp(s.uptimeSecs||0)+'</td>'+
        '<td class="score">'+(s.score||0).toFixed(2)+'</td></tr>';}).join('');
    }else{tb.innerHTML='<tr><td class="empty" colspan="7">no seeders reporting yet</td></tr>';}
    document.getElementById('updated').textContent='updated '+new Date().toLocaleTimeString();
  }catch(e){document.getElementById('status').textContent='OFFLINE';}
}
tick();setInterval(tick,5000);
</script>
</body>
</html>"###;

async fn network_map_page() -> Html<&'static str> {
    Html(MAP_HTML)
}

// ============================================================
//  Anti-spam payment verification (Phase B)
//
//  Periodically reads the SmartHoldem ledger and stamps each app's `paid` flag.
//  An app is PAID when the escrow node received a tx with vendorField
//  `sth:<app_id>` whose amount >= the current oracle publish price. The oracle
//  price itself is read from admin->config `appPublishPrice:<STH>` directives.
// ============================================================

fn http_get_json(url: &str) -> Option<serde_json::Value> {
    match ureq::get(url).timeout(Duration::from_secs(12)).call() {
        Ok(resp) => resp.into_string().ok().and_then(|s| serde_json::from_str(&s).ok()),
        Err(_) => None,
    }
}

/// Round bytes to whole MB (half-up): 1.5 MB -> 2, <0.5 MB -> 0.
fn bytes_to_mb(size_bytes: u64) -> u64 {
    (size_bytes + MIB / 2) / MIB
}

/// UNIFIED dynamic cost (whole STH): base + round(MB) * price_per_mb.
fn compute_cost(base: u64, price_mb: u64, size_bytes: u64) -> u64 {
    base.saturating_add(bytes_to_mb(size_bytes).saturating_mul(price_mb))
}

/// Parse a governance directive `sth_oracle:price_mb=<v>:base=<v>` (also tolerates
/// the `price_mb==<v>` spelling). Returns `(base, price_per_mb)` — both required.
fn parse_oracle_directive(field: &str) -> Option<(u64, u64)> {
    let tok = field.split_whitespace().find(|t| t.starts_with("sth_oracle:"))?;
    let body = tok.strip_prefix("sth_oracle:")?;
    let mut base: Option<u64> = None;
    let mut per_mb: Option<u64> = None;
    for seg in body.split(':') {
        let mut kv = seg.splitn(2, '=');
        let key = kv.next().unwrap_or("").trim();
        let val = kv.next().unwrap_or("").trim_start_matches('=').trim();
        match key {
            "base" => base = val.parse::<u64>().ok(),
            "price_mb" => per_mb = val.parse::<u64>().ok(),
            _ => {}
        }
    }
    match (base, per_mb) {
        (Some(b), Some(p)) => Some((b, p)),
        _ => None,
    }
}

/// Read the newest dynamic-pricing directive (admin -> config) and persist
/// `(base, price_per_mb)` into the tracker sled (`cfg:base_price`,
/// `cfg:price_per_mb`) so it survives restarts and applies WITHOUT a reboot.
/// Falls back to the last persisted values, then the compiled defaults.
fn fetch_oracle_params(db: &sled::Db) -> (u64, u64) {
    let url = format!(
        "{}/transactions?recipientId={}&senderId={}&page=1&limit=100&orderBy=timestamp:desc",
        STH_API, ORACLE_RECIPIENT, ORACLE_SENDER
    );
    if let Some(v) = http_get_json(&url) {
        if let Some(arr) = v["data"].as_array() {
            for t in arr {
                if let Some(f) = t["vendorField"].as_str() {
                    if let Some((base, per_mb)) = parse_oracle_directive(f) {
                        let _ = db.insert(b"cfg:base_price", base.to_string().as_bytes());
                        let _ = db.insert(b"cfg:price_per_mb", per_mb.to_string().as_bytes());
                        let _ = db.flush();
                        return (base, per_mb);
                    }
                }
            }
        }
    }
    let read = |k: &[u8], d: u64| -> u64 {
        db.get(k)
            .ok()
            .flatten()
            .and_then(|v| std::str::from_utf8(&v).ok().and_then(|s| s.trim().parse().ok()))
            .unwrap_or(d)
    };
    (
        read(b"cfg:base_price", DEFAULT_BASE_PRICE),
        read(b"cfg:price_per_mb", DEFAULT_PRICE_PER_MB),
    )
}

/// Largest publish payment (smarthoshi) seen on escrow per app id, from
/// `sth:<id>` memos. The dynamic per-app minimum is compared against this.
fn fetch_paid_amounts() -> HashMap<String, u64> {
    let mut amounts: HashMap<String, u64> = HashMap::new();
    for page in 1..=3u32 {
        let url = format!(
            "{}/transactions?recipientId={}&page={}&limit=100&orderBy=timestamp:desc",
            STH_API, ESCROW_ADDRESS, page
        );
        let Some(v) = http_get_json(&url) else { break };
        let Some(arr) = v["data"].as_array() else { break };
        if arr.is_empty() {
            break;
        }
        for t in arr {
            let amt: u64 = t["amount"]
                .as_str()
                .and_then(|s| s.parse().ok())
                .or_else(|| t["amount"].as_u64())
                .unwrap_or(0);
            // `sth:<id>` (publish/update) — NOT `sth_boost:<id>`
            if let Some(id) = t["vendorField"].as_str().and_then(|f| f.strip_prefix("sth:")) {
                let id = id.trim();
                if !id.is_empty() && amt > 0 {
                    let e = amounts.entry(id.to_string()).or_insert(0);
                    if amt > *e {
                        *e = amt;
                    }
                }
            }
        }
    }
    amounts
}

/// Все платежи публикации/обновления (`sth:<id>`) на escrow с их txid — источник
/// funding-событий. В отличие от fetch_paid_amounts (только максимум) возвращает
/// КАЖДУЮ транзакцию, чтобы каждое платное обновление (reseeding) стало отдельным
/// банком на 5 дней. Дедуп по txid делается на стороне verify_payments.
fn fetch_funding_txs() -> HashMap<String, Vec<(String, u64, bool)>> {
    let mut out: HashMap<String, Vec<(String, u64, bool)>> = HashMap::new();
    for page in 1..=3u32 {
        let url = format!(
            "{}/transactions?recipientId={}&page={}&limit=100&orderBy=timestamp:desc",
            STH_API, ESCROW_ADDRESS, page
        );
        let Some(v) = http_get_json(&url) else { break };
        let Some(arr) = v["data"].as_array() else { break };
        if arr.is_empty() {
            break;
        }
        for t in arr {
            let amt: u64 = t["amount"]
                .as_str()
                .and_then(|s| s.parse().ok())
                .or_else(|| t["amount"].as_u64())
                .unwrap_or(0);
            let txid = t["id"].as_str().unwrap_or("").trim().to_string();
            let field = t["vendorField"].as_str().unwrap_or("");
            // publish/update (`sth:<id>`) — банк, требующий порога цены;
            // boost (`sth_boost:<id>`) — банк без порога (доп. награда сидерам).
            let (id_opt, is_boost) = if let Some(id) = field.strip_prefix("sth_boost:") {
                (Some(id), true)
            } else if let Some(id) = field.strip_prefix("sth:") {
                (Some(id), false)
            } else {
                (None, false)
            };
            if let Some(id) = id_opt {
                let id = id.trim();
                if !id.is_empty() && amt > 0 && !txid.is_empty() {
                    out.entry(id.to_string()).or_default().push((txid, amt, is_boost));
                }
            }
        }
    }
    out
}

/// Accumulated seeding-boost pool (smarthoshi) per app from `sth_boost:<id>` txs.
fn fetch_boost_pools() -> HashMap<String, u64> {
    let mut pools: HashMap<String, u64> = HashMap::new();
    for page in 1..=3u32 {
        let url = format!(
            "{}/transactions?recipientId={}&page={}&limit=100&orderBy=timestamp:desc",
            STH_API, ESCROW_ADDRESS, page
        );
        let Some(v) = http_get_json(&url) else { break };
        let Some(arr) = v["data"].as_array() else { break };
        if arr.is_empty() {
            break;
        }
        for t in arr {
            let amt: u64 = t["amount"]
                .as_str()
                .and_then(|s| s.parse().ok())
                .or_else(|| t["amount"].as_u64())
                .unwrap_or(0);
            if let Some(id) = t["vendorField"].as_str().and_then(|f| f.strip_prefix("sth_boost:")) {
                let id = id.trim();
                if !id.is_empty() && amt > 0 {
                    *pools.entry(id.to_string()).or_insert(0) += amt;
                }
            }
        }
    }
    pools
}

/// One verification pass: recompute the paid flag + boost pool + priority weight
/// for every known app. An app is PAID when an `sth:<id>` payment landed on
/// escrow with amount >= its DYNAMIC cost (base + round(MB)·price_mb) computed
/// from the announced payload weight. Blocking (ureq) — call via spawn_blocking.
fn verify_payments(state: &AppState) {
    let (base, price_mb) = fetch_oracle_params(&state.db);
    let amounts = fetch_paid_amounts();
    let funding_txs = fetch_funding_txs();
    let boosts = fetch_boost_pools();
    let now = now_unix();
    let mut changed: Vec<String> = Vec::new();
    {
        let mut reg = state.reg.lock().unwrap();
        for (id, rec) in reg.apps.iter_mut() {
            let min_sth = compute_cost(base, price_mb, rec.size_bytes);
            let min_smarthoshi = min_sth.saturating_mul(SMARTHOSHI);
            let mut touched = false;

            // Phase G: добавляем НОВЫЕ funding-события (каждое платное обновление —
            // отдельный банк на 5 дней). Дедуп по txid; порог — динамическая цена.
            if let Some(list) = funding_txs.get(id) {
                let known: std::collections::HashSet<String> =
                    rec.funding.iter().map(|f| f.txid.clone()).collect();
                for (txid, amt, is_boost) in list {
                    let threshold = if *is_boost { 1 } else { min_smarthoshi };
                    if *amt >= threshold && !known.contains(txid) {
                        rec.funding.push(FundingEvent {
                            ts: now,
                            amount_smarthoshi: *amt,
                            txid: txid.clone(),
                        });
                        touched = true;
                    }
                }
            }
            // чистим совсем старые события (за пределами окна хранения дедупа)
            let before = rec.funding.len();
            rec.funding.retain(|f| f.ts + FUNDING_RETAIN_SECS > now);
            if rec.funding.len() != before {
                touched = true;
            }
            let new_paid_ts = rec.funding.iter().map(|f| f.ts).min().unwrap_or(0);
            if rec.paid_ts != new_paid_ts {
                rec.paid_ts = new_paid_ts;
                touched = true;
            }

            // paid = есть funding-событие (для выдачи в директории). Fallback на
            // legacy-проверку максимума на случай, если событий ещё нет (миграция).
            let paid_amt = amounts.get(id).copied().unwrap_or(0);
            let now_paid = !rec.funding.is_empty() || (paid_amt >= min_smarthoshi && paid_amt > 0);
            let now_boost = boosts.get(id).copied().unwrap_or(0);
            // priority: 100 base for paid apps + 1 point per boosted whole STH.
            let now_weight = if now_paid {
                100u32.saturating_add((now_boost / SMARTHOSHI) as u32)
            } else {
                0
            };
            if rec.paid != now_paid
                || rec.boost_pool_sth != now_boost
                || rec.priority_weight != now_weight
                || rec.cost_sth != min_sth
                || touched
            {
                rec.paid = now_paid;
                rec.boost_pool_sth = now_boost;
                rec.priority_weight = now_weight;
                rec.cost_sth = min_sth;
                changed.push(id.clone());
            }
        }
        for id in &changed {
            if let Some(r) = reg.apps.get(id) {
                state.persist(r);
            }
        }
    }
    if !changed.is_empty() {
        let _ = state.db.flush();
        tracing::info!(
            "payment-verify: updated {} app(s) (base {} STH + {}/MB, {} paid-ids, {} boosted)",
            changed.len(),
            base,
            price_mb,
            amounts.len(),
            boosts.len()
        );
    }
}


// ============================================================
//  Entrypoint
// ============================================================

#[tokio::main]
async fn main() {
    // Подхватываем настройки из `.env` (если файл рядом с бинарником или в текущей
    // директории). Даёт удобство хостинга на VPS: одна правка `.env` вместо экспорта
    // переменных вручную. Ошибка отсутствия файла игнорируется — env-переменные
    // всё ещё можно задать через shell/systemd EnvironmentFile.
    let _ = dotenvy::dotenv();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "smartnet_tracker=info,tower_http=warn".into()),
        )
        .init();

    // DB location (override with SMARTNET_TRACKER_DB).
    let db_path =
        std::env::var("SMARTNET_TRACKER_DB").unwrap_or_else(|_| "./tracker-data".to_string());

    // `--wipe`: clear the persisted directory and exit (operator maintenance).
    if std::env::args().any(|a| a == "--wipe") {
        match std::fs::remove_dir_all(&db_path) {
            Ok(_) => println!("tracker DB wiped: {}", db_path),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                println!("tracker DB already empty: {}", db_path)
            }
            Err(e) => {
                eprintln!("failed to wipe tracker DB {}: {}", db_path, e);
                std::process::exit(1);
            }
        }
        return;
    }

    let port: u16 = std::env::var("SMARTNET_TRACKER_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_PORT);
    let ttl_secs: u64 = std::env::var("SMARTNET_TRACKER_TTL")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_TTL_SECS);
    // announce logging is ON by default; disable with
    // SMARTNET_TRACKER_LOG_ANNOUNCE=0 (also accepts false/off/no).
    let log_announce = std::env::var("SMARTNET_TRACKER_LOG_ANNOUNCE")
        .map(|v| !matches!(v.trim().to_lowercase().as_str(), "0" | "false" | "off" | "no"))
        .unwrap_or(true);
    // Global monetization kill-switch (default ON). Set ENABLE_INCENTIVIZED_SEEDING=
    // 0/false/off/no to expose ALL apps in /apps regardless of on-chain payment.
    let incentivized = std::env::var("ENABLE_INCENTIVIZED_SEEDING")
        .map(|v| !matches!(v.trim().to_lowercase().as_str(), "0" | "false" | "off" | "no"))
        .unwrap_or(true);

    let ttl = Duration::from_secs(ttl_secs);
    let db = sled::open(&db_path).expect("failed to open tracker sled DB");
    let mut registry = load_registry(&db, ttl);
    let tombstones = load_tombstones(&db);
    // Never resurrect a tombstoned app from the persisted directory.
    registry.apps.retain(|id, _| !tombstones.contains_key(id));
    tracing::info!(
        "loaded {} app(s) from persistent store at {} ({} tombstoned)",
        registry.apps.len(),
        db_path,
        tombstones.len()
    );

    let state = AppState {
        reg: Arc::new(Mutex::new(registry)),
        ttl,
        started: Instant::now(),
        log_announce,
        stats: Arc::new(Stats::default()),
        db,
        seeders: Arc::new(Mutex::new(HashMap::new())),
        tombstones: Arc::new(Mutex::new(tombstones)),
        incentivized,
        dht_pool: Arc::new(Mutex::new(HashMap::new())),
        operator_sk: std::env::var("OPERATOR_SECRET")
            .ok()
            .and_then(|h| hex::decode(h.trim()).ok())
            .and_then(|b| SecretKey::from_slice(&b).ok()),
    };
    if state.operator_sk.is_some() {
        let pk = PublicKey::from_secret_key(&Secp256k1::new(), state.operator_sk.as_ref().unwrap());
        tracing::info!("operator signing ENABLED — /seeders-dht pubkey: {}", hex::encode(pk.serialize()));
    }

    // background pruner so stale providers don't linger between requests
    {
        let bg = state.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(30));
            loop {
                tick.tick().await;
                bg.prune();
            }
        });
    }

    // Network Map: periodically scrape each seeder's /metrics for fresh
    // contribution stats and recompute the Byte-Hours leaderboard score.
    {
        let bg = state.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(60));
            loop {
                tick.tick().await;
                scrape_seeders(&bg).await;
                record_network_history(&bg);
            }
        });
    }

    // Anti-spam (Phase B): every 5 min re-verify on-chain publish payments and
    // stamp each app's `paid` flag (drives the public directory exposure filter).
    {
        let bg = state.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(300));
            loop {
                tick.tick().await;
                let s = bg.clone();
                let _ = tokio::task::spawn_blocking(move || verify_payments(&s)).await;
            }
        });
    }

    // Official Repository: scan both on-chain registries on boot + every 24h
    // (10-min retry while the blockchain is unreachable).
    {
        let bg = state.clone();
        official_load(&bg);
        tokio::spawn(async move {
            loop {
                let s = bg.clone();
                let ok = tokio::task::spawn_blocking(move || official_refresh(&s).is_ok())
                    .await
                    .unwrap_or(false);
                tokio::time::sleep(Duration::from_secs(if ok { 86_400 } else { 600 })).await;
            }
        });
    }

    let cors = CorsLayer::new().allow_origin(Any).allow_methods(Any).allow_headers(Any);

    let app = Router::new()
        .route("/", get(index))
        .route("/announce", post(announce))
        .route("/delete", post(delete_app_handler))
        .route("/deleted", get(deleted_apps))
        .route("/apps", get(list_apps))
        .route("/app/{id}", get(get_app))
        .route("/app/{id}/seeders", get(app_seeders))
        .route("/seeds", get(seeds))
        .route("/seeders", get(seeders_list))
        .route("/seeders-dht", get(seeders_dht))
        .route("/operator-pubkey", get(operator_pubkey))
        .route("/dht", get(dht_bootstrap))
        .route("/network/storage", get(network_storage))
        .route("/seeder/heartbeat", post(seeder_heartbeat))
        .route("/seeder/heartbeat/{address}", get(seeder_uptime))
        .route("/map", get(network_map_page))
        .route("/stats", get(stats))
        .route("/health", get(health))
        .layer(cors)
        .with_state(state);

    let addr = format!("0.0.0.0:{}", port);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("failed to bind tracker port");
    tracing::info!("SmartNet tracker listening on {} (ttl {}s)", addr, ttl_secs);
    tracing::info!(
        "incentivized seeding: {} (toggle with ENABLE_INCENTIVIZED_SEEDING)",
        if incentivized { "ON" } else { "OFF — exposing ALL apps (emergency mode)" }
    );
    tracing::info!(
        "announce logging: {} (toggle with SMARTNET_TRACKER_LOG_ANNOUNCE)",
        if log_announce { "ON" } else { "OFF" }
    );
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .expect("tracker server error");
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutting down");
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::SecretKey;

    fn signed_app(secret: &str, name: &str, desc: &str, merkle: &str) -> AppAnnounce {
        let sk = SecretKey::from_slice(&sha256(secret.as_bytes())).unwrap();
        let secp = Secp256k1::new();
        let pk = PublicKey::from_secret_key(&secp, &sk);
        let id = address_from_pubkey(&pk.serialize());
        let digest = sha256(format!("{}|{}|{}|{}", id, name, desc, merkle).as_bytes());
        let msg = Message::from_digest_slice(&digest).unwrap();
        let signature = hex::encode(secp.sign_ecdsa(&msg, &sk).serialize_compact());
        AppAnnounce {
            id,
            name: name.into(),
            description: desc.into(),
            tags: vec!["demo".into()],
            merkle: merkle.into(),
            version: 1,
            updated: String::new(),
            hash: "h".into(),
            size: 0,
            signature,
            public_key: hex::encode(pk.serialize()),
            owner: String::new(),
            logo: String::new(),
            preview: String::new(),
        }
    }

    /// canon v2: owner included in the signed digest.
    fn signed_app_v2(secret: &str, name: &str, desc: &str, merkle: &str, owner: &str) -> AppAnnounce {
        let sk = SecretKey::from_slice(&sha256(secret.as_bytes())).unwrap();
        let secp = Secp256k1::new();
        let pk = PublicKey::from_secret_key(&secp, &sk);
        let id = address_from_pubkey(&pk.serialize());
        let digest = sha256(format!("{}|{}|{}|{}|{}", id, name, desc, merkle, owner).as_bytes());
        let msg = Message::from_digest_slice(&digest).unwrap();
        let signature = hex::encode(secp.sign_ecdsa(&msg, &sk).serialize_compact());
        AppAnnounce {
            id,
            name: name.into(),
            description: desc.into(),
            tags: vec!["demo".into()],
            merkle: merkle.into(),
            version: 1,
            updated: String::new(),
            hash: "h".into(),
            size: 0,
            signature,
            public_key: hex::encode(pk.serialize()),
            owner: owner.into(),
            logo: String::new(),
            preview: String::new(),
        }
    }

    #[test]
    fn accepts_valid_signature() {
        let a = signed_app("seed-a", "App A", "desc", "mk");
        assert!(verify_announce(&a).is_ok());
    }

    #[test]
    fn legacy_canon_spoofed_owner_not_trusted() {
        // легаси-подпись (без owner) + приписанный чужой owner → анонс валиден,
        // но owner НЕ считается подтверждённым (никакого бейджа Official)
        let mut a = signed_app("seed-e", "App E", "desc", "mk");
        a.owner = "SXdXoyUAjUyyCC5LES6KH1XS1ewbBB4Dfu".into();
        assert_eq!(verify_announce(&a).unwrap(), false);
    }

    #[test]
    fn v2_canon_owner_trusted() {
        let owner = "SXdXoyUAjUyyCC5LES6KH1XS1ewbBB4Dfu";
        let a = signed_app_v2("seed-f", "App F", "desc", "mk", owner);
        assert_eq!(verify_announce(&a).unwrap(), true);
        // подмена owner после подписи ломает v2-канон и не проходит как легаси
        let mut b = signed_app_v2("seed-g", "App G", "desc", "mk", owner);
        b.owner = "SeZLuyhhYf2qxs4ArPJ71oEu3x8EsVw51C".into();
        assert!(verify_announce(&b).is_err());
    }

    #[test]
    fn rejects_tampered_name() {
        let mut a = signed_app("seed-b", "App B", "desc", "mk");
        a.name = "Hacked".into();
        assert!(verify_announce(&a).is_err());
    }

    #[test]
    fn rejects_id_pubkey_mismatch() {
        let mut a = signed_app("seed-c", "App C", "desc", "mk");
        a.id = "SXdXoyUAjUyyCC5LES6KH1XS1ewbBB4Dfu".into();
        assert_eq!(verify_announce(&a).unwrap_err(), "id-mismatch");
    }

    #[test]
    fn address_matches_known_vector() {
        // SmartHoldem reference: derived 'S...' address shape with version byte 0x3f
        let sk = SecretKey::from_slice(&sha256(b"any")).unwrap();
        let secp = Secp256k1::new();
        let pk = PublicKey::from_secret_key(&secp, &sk);
        let addr = address_from_pubkey(&pk.serialize());
        assert!(addr.starts_with('S'));
    }

    #[test]
    fn parses_governance_oracle_directive() {
        assert_eq!(parse_oracle_directive("sth_oracle:price_mb=2:base=10"), Some((10, 2)));
        assert_eq!(parse_oracle_directive("sth_oracle:base=25:price_mb==4"), Some((25, 4)));
        assert_eq!(parse_oracle_directive("sth_oracle:base=10"), None);
        assert_eq!(parse_oracle_directive("appPublishPrice:100"), None);
    }

    #[test]
    fn dynamic_cost_formula() {
        assert_eq!(bytes_to_mb(0), 0);
        assert_eq!(bytes_to_mb(MIB / 2), 1);
        assert_eq!(bytes_to_mb(MIB + MIB / 2), 2);
        // base=10, 2/MB; 0 bytes -> 10; ~3MB -> 10 + 3*2 = 16
        assert_eq!(compute_cost(10, 2, 0), 10);
        assert_eq!(compute_cost(10, 2, 3 * MIB), 16);
    }
}
