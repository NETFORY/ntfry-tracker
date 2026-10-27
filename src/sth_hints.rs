//! SmartHoldem sth-core hints (v1.8.0): адресные подсказки (relay/IP) для P2P-узлов
//! `api://<EndpointId>/sth-core`, которые присылают сами клиенты после удачного
//! соединения. Нужны как ЗАПАСНОЙ путь, когда discovery (DNS n0 / pkarr / DHT) не
//! находит узел; безопасность не страдает iroh аутентифицирует узел по EndpointId
//! (QUIC TLS), ложный адрес просто не подключится.
//!
//! * `POST /sth/hint`  `{ "id": "<hex64>", "addrs": ["relay:https://…", "ip:1.2.3.4:443"], "reporter": "…" }`
//! * `GET  /sth/hints` -> `{ "ts": …, "nodes": [{ "id", "addrs", "reporters", "age" }] }`
//!
//! Записи живут `TTL_SECS` с последнего репорта, адреса объединение (реле первыми),
//! не больше `MAX_ADDRS`; всего не больше `MAX_IDS` узлов (вытесняются самые старые).

use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};

use crate::{now_unix, AppState};

pub type SthHintMap = Arc<Mutex<HashMap<String, HintEntry>>>;

pub fn new_map() -> SthHintMap {
    Arc::new(Mutex::new(HashMap::new()))
}

const TTL_SECS: u64 = 12 * 3600;
const MAX_IDS: usize = 128;
const MAX_ADDRS: usize = 8;
const MAX_REPORTERS: usize = 64;
/// Один репортёр не чаще раза в 30 с на узел.
const MIN_REPORT_GAP: u64 = 30;

#[derive(Debug, Clone, Serialize)]
pub struct HintEntry {
    pub addrs: Vec<String>,
    #[serde(skip)]
    pub reporters: HashSet<String>,
    #[serde(skip)]
    pub last_by_reporter: HashMap<String, u64>,
    pub ts: u64,
}

#[derive(Debug, Deserialize)]
pub struct HintReport {
    pub id: String,
    pub addrs: Vec<String>,
    #[serde(default)]
    pub reporter: String,
}

#[derive(Debug, Serialize)]
pub struct HintOut {
    pub id: String,
    pub addrs: Vec<String>,
    pub reporters: usize,
    pub age: u64,
}

fn valid_id(id: &str) -> bool {
    id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Допустимы `relay:https://host/` и `ip:<публичный sockaddr>`.
fn valid_addr(a: &str) -> bool {
    if let Some(u) = a.strip_prefix("relay:") {
        return u.starts_with("https://") && u.len() <= 128 && !u.contains(char::is_whitespace);
    }
    if let Some(s) = a.strip_prefix("ip:") {
        return match s.parse::<SocketAddr>() {
            Ok(sa) => sa.port() != 0 && is_public(sa.ip()),
            Err(_) => false,
        };
    }
    false
}

fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_unspecified() || v4.is_broadcast() || v4.is_documentation()
                || (v4.octets()[0] == 100 && (64..=127).contains(&v4.octets()[1])))
        }
        IpAddr::V6(v6) => {
            let seg = v6.segments();
            !(v6.is_loopback() || v6.is_unspecified() || (seg[0] & 0xfe00) == 0xfc00 || (seg[0] & 0xffc0) == 0xfe80)
        }
    }
}

fn prune(map: &mut HashMap<String, HintEntry>, now: u64) {
    map.retain(|_, e| now.saturating_sub(e.ts) <= TTL_SECS);
    while map.len() > MAX_IDS {
        if let Some(oldest) = map.iter().min_by_key(|(_, e)| e.ts).map(|(k, _)| k.clone()) {
            map.remove(&oldest);
        } else {
            break;
        }
    }
}

/// Объединить адреса: реле первыми, без дублей, не больше MAX_ADDRS; новые вперёд.
fn merge_addrs(old: &[String], new: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for a in new.iter().chain(old.iter()) {
        if a.starts_with("relay:") && !out.contains(a) {
            out.push(a.clone());
        }
    }
    for a in new.iter().chain(old.iter()) {
        if a.starts_with("ip:") && !out.contains(a) {
            out.push(a.clone());
        }
    }
    out.truncate(MAX_ADDRS);
    out
}

pub async fn sth_hint(State(state): State<AppState>, Json(r): Json<HintReport>) -> (StatusCode, Json<serde_json::Value>) {
    let id = r.id.trim().to_ascii_lowercase();
    if !valid_id(&id) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "bad id" })));
    }
    let addrs: Vec<String> = r.addrs.iter().map(|a| a.trim().to_string()).filter(|a| valid_addr(a)).take(MAX_ADDRS).collect();
    if addrs.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "no valid addrs" })));
    }
    let reporter: String = r.reporter.chars().take(64).collect();
    let now = now_unix();
    let mut map = state.sth_hints.lock().unwrap();
    prune(&mut map, now);
    let e = map.entry(id).or_insert_with(|| HintEntry { addrs: Vec::new(), reporters: HashSet::new(), last_by_reporter: HashMap::new(), ts: now });
    if !reporter.is_empty() {
        if let Some(last) = e.last_by_reporter.get(&reporter) {
            if now.saturating_sub(*last) < MIN_REPORT_GAP {
                return (StatusCode::TOO_MANY_REQUESTS, Json(serde_json::json!({ "error": "slow down" })));
            }
        }
        if e.reporters.len() < MAX_REPORTERS || e.reporters.contains(&reporter) {
            e.reporters.insert(reporter.clone());
            e.last_by_reporter.insert(reporter, now);
        }
    }
    e.addrs = merge_addrs(&e.addrs, &addrs);
    e.ts = now;
    (StatusCode::OK, Json(serde_json::json!({ "ok": true, "addrs": e.addrs.len(), "reporters": e.reporters.len() })))
}

pub async fn sth_hints(State(state): State<AppState>) -> Json<serde_json::Value> {
    let now = now_unix();
    let mut map = state.sth_hints.lock().unwrap();
    prune(&mut map, now);
    let mut nodes: Vec<HintOut> = map
        .iter()
        .map(|(id, e)| HintOut { id: id.clone(), addrs: e.addrs.clone(), reporters: e.reporters.len(), age: now.saturating_sub(e.ts) })
        .collect();
    drop(map);
    nodes.sort_by(|a, b| b.reporters.cmp(&a.reporters).then(a.age.cmp(&b.age)));
    Json(serde_json::json!({ "ts": now, "nodes": nodes }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addr_validation() {
        assert!(valid_addr("relay:https://n1.example.net/"));
        assert!(valid_addr("ip:95.217.132.244:443"));
        assert!(valid_addr("ip:[2a01:4f8::1]:443"));
        assert!(!valid_addr("ip:192.168.1.2:443"));
        assert!(!valid_addr("ip:127.0.0.1:443"));
        assert!(!valid_addr("ip:[fe80::1]:443"));
        assert!(!valid_addr("relay:http://plain/"));
        assert!(!valid_addr("foo:bar"));
    }

    #[test]
    fn merge_prefers_relay_and_new() {
        let old = vec!["ip:1.1.1.1:1".to_string(), "relay:https://a/".to_string()];
        let new = vec!["ip:2.2.2.2:2".to_string(), "relay:https://b/".to_string(), "ip:1.1.1.1:1".to_string()];
        let m = merge_addrs(&old, &new);
        assert_eq!(m, vec!["relay:https://b/", "relay:https://a/", "ip:2.2.2.2:2", "ip:1.1.1.1:1"]);
    }
}

// ---------------------------------------------------------------------------
//  v1.9.0: самоанонс провайдеров (`netfory-provider ≥ 0.7.0`) -> живой пул узлов.
//  `POST /sth/announce` подписанный ed25519 heartbeat самого узла (id = pubkey),
//  `GET  /sth/pool`     живые узлы (≤ POOL_TTL_SECS с последнего heartbeat'а) с
//  адресами и списком провайдеров. Адреса также попадают в /sth/hints старые
//  клиенты (1.135.215+) получают их как подсказки.
// ---------------------------------------------------------------------------

/// Узел живой, если анонсировался не позже этого (provider шлёт раз в 60 с).
const POOL_TTL_SECS: u64 = 300;
const POOL_MAX: usize = 256;
const ANNOUNCE_TS_SKEW_SECS: u64 = 300;

pub type SthPoolMap = Arc<Mutex<HashMap<String, PoolEntry>>>;

pub fn new_pool() -> SthPoolMap {
    Arc::new(Mutex::new(HashMap::new()))
}

#[derive(Debug, Clone, Serialize)]
pub struct PoolEntry {
    pub ver: String,
    pub providers: Vec<String>,
    /// `relay:https://…` / `ip:host:port` формат peerbook клиента.
    pub addrs: Vec<String>,
    pub ts: u64,
}

#[derive(Debug, Deserialize)]
pub struct SthAnnounce {
    pub id: String,
    #[serde(default)]
    pub ver: String,
    #[serde(default)]
    pub providers: Vec<String>,
    /// Публичные `ip:port` (без префикса), как у pq-web.
    #[serde(default)]
    pub addrs: Vec<String>,
    #[serde(default)]
    pub relay: String,
    pub ts: u64,
    pub sig: String,
}

/// Канон v1 1:1 с `netfory-provider/src/announce.rs::canon`.
fn sth_announce_canon(id: &str, ver: &str, ts: u64, providers: &[String], addrs: &[String], relay: &str) -> String {
    format!("sth-announce|{id}|{ver}|{ts}|{}|{}|{relay}", providers.join(","), addrs.join(","))
}

fn sth_announce_verify(a: &SthAnnounce) -> Result<(), &'static str> {
    let pk_bytes = hex::decode(a.id.trim()).map_err(|_| "bad-id-hex")?;
    let pk_arr: [u8; 32] = pk_bytes.as_slice().try_into().map_err(|_| "bad-id-len")?;
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&pk_arr).map_err(|_| "bad-pubkey")?;
    let sig_bytes = hex::decode(a.sig.trim()).map_err(|_| "bad-sig-hex")?;
    let sig_arr: [u8; 64] = sig_bytes.as_slice().try_into().map_err(|_| "bad-sig-len")?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
    let canon = sth_announce_canon(a.id.trim(), a.ver.trim(), a.ts, &a.providers, &a.addrs, a.relay.trim());
    vk.verify_strict(canon.as_bytes(), &sig).map_err(|_| "bad-signature")
}

pub async fn sth_announce(State(state): State<AppState>, Json(a): Json<SthAnnounce>) -> (StatusCode, Json<serde_json::Value>) {
    let id = a.id.trim().to_ascii_lowercase();
    let now = now_unix();
    if !valid_id(&id) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "ok": false, "error": "bad-id" })));
    }
    if a.ts + ANNOUNCE_TS_SKEW_SECS < now || a.ts > now + ANNOUNCE_TS_SKEW_SECS {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "ok": false, "error": "stale-ts", "now": now })));
    }
    if let Err(e) = sth_announce_verify(&a) {
        tracing::warn!("sth announce REJECTED id={} ({})", id, e);
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "ok": false, "error": e })));
    }
    // адреса в формате peerbook: relay первым, затем публичные ip:port
    let mut addrs: Vec<String> = Vec::new();
    let relay = a.relay.trim();
    if !relay.is_empty() {
        let r = format!("relay:{relay}");
        if valid_addr(&r) {
            addrs.push(r);
        }
    }
    for s in a.addrs.iter().take(6) {
        let x = format!("ip:{}", s.trim());
        if valid_addr(&x) && !addrs.contains(&x) {
            addrs.push(x);
        }
    }
    let providers: Vec<String> = a.providers.iter().map(|p| p.trim().to_ascii_lowercase()).filter(|p| !p.is_empty() && p.len() <= 32).take(16).collect();
    let ver: String = a.ver.trim().chars().take(24).collect();

    let mut pool = state.sth_pool.lock().unwrap();
    pool.retain(|_, e| now.saturating_sub(e.ts) <= POOL_TTL_SECS);
    let is_new = !pool.contains_key(&id);
    if is_new && pool.len() >= POOL_MAX {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({ "ok": false, "error": "full" })));
    }
    if is_new {
        tracing::info!("sth node ONLINE id={} ver={} providers=[{}] addrs={}", id, ver, providers.join(","), addrs.len());
    }
    pool.insert(id.clone(), PoolEntry { ver, providers, addrs: addrs.clone(), ts: now });
    drop(pool);

    // те же адреса в подсказки для клиентов без /sth/pool
    if !addrs.is_empty() {
        let mut map = state.sth_hints.lock().unwrap();
        prune(&mut map, now);
        let e = map.entry(id).or_insert_with(|| HintEntry { addrs: Vec::new(), reporters: HashSet::new(), last_by_reporter: HashMap::new(), ts: now });
        e.addrs = merge_addrs(&e.addrs, &addrs);
        e.reporters.insert("self".to_string());
        e.ts = now;
    }
    (StatusCode::OK, Json(serde_json::json!({ "ok": true, "ttlSecs": POOL_TTL_SECS, "now": now })))
}

#[derive(Debug, Serialize)]
pub struct PoolOut {
    pub id: String,
    pub ver: String,
    pub providers: Vec<String>,
    pub addrs: Vec<String>,
    pub age: u64,
}

pub async fn sth_pool(State(state): State<AppState>) -> Json<serde_json::Value> {
    let now = now_unix();
    let mut pool = state.sth_pool.lock().unwrap();
    pool.retain(|_, e| now.saturating_sub(e.ts) <= POOL_TTL_SECS);
    let mut nodes: Vec<PoolOut> = pool
        .iter()
        .map(|(id, e)| PoolOut { id: id.clone(), ver: e.ver.clone(), providers: e.providers.clone(), addrs: e.addrs.clone(), age: now.saturating_sub(e.ts) })
        .collect();
    drop(pool);
    nodes.sort_by(|a, b| a.age.cmp(&b.age).then(a.id.cmp(&b.id)));
    Json(serde_json::json!({ "ts": now, "ttlSecs": POOL_TTL_SECS, "nodes": nodes }))
}
