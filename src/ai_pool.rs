// ============================================================
//  ai_pool Netfory AI Pool aggregation (Phase 1)
//
//  Приём подписанных AI-heartbeat'ов от opt-in нод (GPU/CPU/RAM метрики),
//  in-memory реестр с TTL 45s и агрегированные AI Stats для клиентского UI.
//
//  Digest ОБЯЗАН совпадать с клиентом (ai_telemetry/heartbeat.rs):
//    sha256("staih|addr|ts|model|vramT|vramF|tflops*10|thr|ramT|ramF")
//
//  Endpoints:
//    POST /v1/ai/heartbeat телеметрия ноды (подпись secp256k1)
//    GET  /v1/ai/stats     суммарные мощности активных нод
// ============================================================

use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use secp256k1::ecdsa::Signature;
use secp256k1::{Message, PublicKey, Secp256k1};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::{address_from_pubkey, now_unix, sha256, AppState};

// ---------- реестр тикетов моделей: alias → "<hash>@<nodeId>" ----------
// DEV-нода регистрирует тикет при publish-model --alias; шлюзы скачивают
// draft/модель по alias (--draft qwen3-0.6b, fetch-model qwen3-0.6b).

const TICKETS_MAX: usize = 1000;
/// alias выпадает из каталога, если источник молчит больше суток
/// (живой publish-model переанонсирует тикет каждые 60 секунд)
const TICKET_TTL_SECS: u64 = 86_400;

fn prune_tickets(map: &mut HashMap<String, (String, u64)>, now: u64) {
    map.retain(|_, (_, ts)| now.saturating_sub(*ts) <= TICKET_TTL_SECS);
}

fn tickets() -> &'static Mutex<HashMap<String, (String, u64)>> {
    static T: std::sync::OnceLock<Mutex<HashMap<String, (String, u64)>>> = std::sync::OnceLock::new();
    T.get_or_init(|| Mutex::new(HashMap::new()))
}

fn alias_ok(a: &str) -> bool {
    !a.is_empty()
        && a.len() <= 64
        && a.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

#[derive(Deserialize)]
pub struct TicketIn {
    pub alias: String,
    pub ticket: String,
}

#[derive(Deserialize)]
pub struct TicketQuery {
    pub alias: String,
}

/// POST /v1/ai/model-ticket {alias, ticket} регистрация тикета модели.
pub async fn ai_model_ticket_put(Json(b): Json<TicketIn>) -> (StatusCode, Json<serde_json::Value>) {
    let alias = b.alias.trim().to_lowercase();
    let ticket = b.ticket.trim().to_string();
    let valid_ticket = ticket
        .split_once('@')
        .map(|(h, n)| !h.is_empty() && !n.is_empty() && ticket.len() <= 256)
        .unwrap_or(false);
    if !alias_ok(&alias) || !valid_ticket {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "bad alias/ticket"})));
    }
    let mut map = crate::lk(tickets());
    prune_tickets(&mut map, now_unix());
    if map.len() >= TICKETS_MAX && !map.contains_key(&alias) {
        // вытесняем самый старый
        if let Some(old) = map.iter().min_by_key(|(_, (_, ts))| *ts).map(|(k, _)| k.clone()) {
            map.remove(&old);
        }
    }
    map.insert(alias.clone(), (ticket, now_unix()));
    (StatusCode::OK, Json(serde_json::json!({"ok": true, "alias": alias})))
}

/// GET /v1/ai/model-ticket?alias=x тикет модели по alias.
pub async fn ai_model_ticket_get(Query(q): Query<TicketQuery>) -> (StatusCode, Json<serde_json::Value>) {
    let alias = q.alias.trim().to_lowercase();
    let mut map = crate::lk(tickets());
    prune_tickets(&mut map, now_unix());
    match map.get(&alias) {
        Some((ticket, ts)) => (
            StatusCode::OK,
            Json(serde_json::json!({"alias": alias, "ticket": ticket, "registeredAt": ts})),
        ),
        None => (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "alias не зарегистрирован"}))),
    }
}

/// Текущее состояние мьютекса каталога тикетов (для отчёта вотчдога).
pub fn tickets_state() -> &'static str {
    match tickets().try_lock() {
        Ok(_) => "free",
        Err(std::sync::TryLockError::Poisoned(_)) => "POISONED",
        Err(std::sync::TryLockError::WouldBlock) => "BUSY",
    }
}

/// Анти-replay: heartbeat старше/новее 30 секунд отбрасывается.
const AI_MAX_DRIFT: u64 = 30;
/// Нода выпадает из пула, пропустив 3 цикла по 15 секунд.
const AI_TTL_SECS: u64 = 45;
/// Жёсткий кап реестра (анти-спам / память).
const AI_POOL_MAX: usize = 100_000;

pub type AiPoolMap = Arc<Mutex<HashMap<String, AiNodeEntry>>>;

pub fn new_pool() -> AiPoolMap {
    Arc::new(Mutex::new(HashMap::new()))
}

#[derive(Debug, Clone)]
pub struct AiNodeEntry {
    pub last_seen: u64,
    pub has_gpu: bool,
    pub vram_total_mb: u64,
    pub vram_free_mb: u64,
    pub tflops_fp16: f64,
    pub threads: u32,
    pub ram_total_mb: u64,
    pub ram_free_mb: u64,
    /// ai://-адрес воркера (iroh NodeId) если нода принимает инференс
    pub iroh_node_id: Option<String>,
    /// alias'ы загруженных моделей
    pub models: Vec<String>,
    /// перегрев/лимит диспетчер такие ноды не выбирает
    pub throttled: bool,
    pub cuda_capability: Option<String>,
    /// готова принять LoadShard от шлюза (авто-разрезка)
    pub shard_ready: bool,
    /// версия бинарника ноды
    pub version: Option<String>,
    /// метрики конвейера шлюза
    pub pipe: Option<serde_json::Value>,
    /// цена инференса, STH за 1 млн токенов (0 = бесплатно)
    pub price_per_mtok: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AiGpu {
    #[serde(default)]
    model: String,
    #[serde(default)]
    vram_total_mb: u64,
    #[serde(default)]
    vram_free_mb: u64,
    #[serde(default)]
    tflops_fp16: f64,
    #[serde(default)]
    throttled: bool,
    #[serde(default)]
    cuda_capability: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AiCpu {
    #[serde(default)]
    threads: u32,
    #[serde(default)]
    ram_total_mb: u64,
    #[serde(default)]
    ram_free_mb: u64,
}

#[derive(Debug, Deserialize)]
pub struct AiMetrics {
    #[serde(default)]
    gpu: Option<AiGpu>,
    cpu: AiCpu,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AiHeartbeat {
    node_id: String,
    timestamp: u64,
    #[serde(default)]
    ai_pool_enabled: bool,
    public_key: String,
    signature: String,
    /// неподписанные поля от воркера (ai://-маршрутизация)
    #[serde(default)]
    iroh_node_id: Option<String>,
    #[serde(default)]
    models: Vec<String>,
    #[serde(default)]
    shard_ready: bool,
    /// версия бинарника ноды (неподписанная, информационная)
    #[serde(default)]
    version: Option<String>,
    /// метрики конвейера шлюза {ttftMs, tokPerSec, requests, batch}
    #[serde(default)]
    pipe: Option<serde_json::Value>,
    /// цена инференса, STH за 1 млн токенов (0 = бесплатно, неподписанная)
    #[serde(default)]
    price_per_mtok: u64,
    metrics: AiMetrics,
}

fn ai_digest(hb: &AiHeartbeat) -> [u8; 32] {
    let (model, vt, vf, t10) = match &hb.metrics.gpu {
        Some(g) => (
            g.model.clone(),
            g.vram_total_mb,
            g.vram_free_mb,
            (g.tflops_fp16 * 10.0).round() as u64,
        ),
        None => (String::new(), 0, 0, 0),
    };
    let c = &hb.metrics.cpu;
    sha256(
        format!(
            "staih|{}|{}|{model}|{vt}|{vf}|{t10}|{}|{}|{}",
            hb.node_id, hb.timestamp, c.threads, c.ram_total_mb, c.ram_free_mb
        )
        .as_bytes(),
    )
}

fn verify_ai_heartbeat(hb: &AiHeartbeat) -> Result<(), &'static str> {
    let pk_bytes = hex::decode(hb.public_key.trim()).map_err(|_| "bad-pubkey-hex")?;
    let pk = PublicKey::from_slice(&pk_bytes).map_err(|_| "bad-pubkey")?;
    if address_from_pubkey(&pk.serialize()) != hb.node_id {
        return Err("address-mismatch");
    }
    let digest = ai_digest(hb);
    let sig_bytes = hex::decode(hb.signature.trim()).map_err(|_| "bad-sig-hex")?;
    let sig = Signature::from_compact(&sig_bytes).map_err(|_| "bad-sig")?;
    let msg = Message::from_digest_slice(&digest).map_err(|_| "bad-digest")?;
    Secp256k1::verification_only()
        .verify_ecdsa(&msg, &sig, &pk)
        .map_err(|_| "sig-verify-failed")
}

fn prune(pool: &mut HashMap<String, AiNodeEntry>, now: u64) {
    pool.retain(|_, e| now.saturating_sub(e.last_seen) <= AI_TTL_SECS);
}

pub async fn ai_heartbeat(
    State(state): State<AppState>,
    Json(hb): Json<AiHeartbeat>,
) -> Result<StatusCode, (StatusCode, String)> {
    let now = now_unix();
    if now.abs_diff(hb.timestamp) > AI_MAX_DRIFT {
        return Err((StatusCode::BAD_REQUEST, "clock drift too large".into()));
    }
    if let Err(e) = verify_ai_heartbeat(&hb) {
        return Err((StatusCode::UNAUTHORIZED, e.into()));
    }
    let mut pool = crate::lk(&state.ai_pool);
    prune(&mut pool, now);
    if !hb.ai_pool_enabled {
        // вежливый opt-out: нода выключила AI Pool убираем сразу
        pool.remove(&hb.node_id);
        return Ok(StatusCode::OK);
    }
    if pool.len() >= AI_POOL_MAX && !pool.contains_key(&hb.node_id) {
        return Err((StatusCode::TOO_MANY_REQUESTS, "ai pool is full".into()));
    }
    let (has_gpu, vt, vf, tf) = match &hb.metrics.gpu {
        Some(g) => (
            !g.model.is_empty() && g.vram_total_mb > 0,
            g.vram_total_mb,
            g.vram_free_mb.min(g.vram_total_mb),
            g.tflops_fp16.clamp(0.0, 100_000.0),
        ),
        None => (false, 0, 0, 0.0),
    };
    let c = &hb.metrics.cpu;
    let (throttled, cuda_cc) = match &hb.metrics.gpu {
        Some(g) => (g.throttled, g.cuda_capability.clone()),
        None => (false, None),
    };
    pool.insert(
        hb.node_id.clone(),
        AiNodeEntry {
            last_seen: now,
            has_gpu,
            vram_total_mb: vt,
            vram_free_mb: vf,
            tflops_fp16: tf,
            threads: c.threads.min(4096),
            ram_total_mb: c.ram_total_mb,
            ram_free_mb: c.ram_free_mb.min(c.ram_total_mb),
            iroh_node_id: hb.iroh_node_id.clone(),
            models: hb.models.clone(),
            throttled,
            cuda_capability: cuda_cc,
            shard_ready: hb.shard_ready,
            version: hb.version.clone(),
            pipe: hb.pipe.clone(),
            price_per_mtok: hb.price_per_mtok,
        },
    );
    Ok(StatusCode::OK)
}

/// Диспетчер: выбрать лучшего исполнителя для инференса.
/// Фильтры: есть GPU, не throttled, есть ai://-адрес, модель загружена (если
/// задана ?model=), VRAM ≥ ?minVramMb. Сортировка: max VRAM free → max TFLOPS.
#[derive(Deserialize)]
pub struct PickQuery {
    #[serde(default)]
    model: Option<String>,
    #[serde(default, alias = "minVramMb")]
    min_vram_mb: Option<u64>,
}

pub async fn ai_pick(
    State(state): State<AppState>,
    Query(q): Query<PickQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let now = now_unix();
    let mut pool = crate::lk(&state.ai_pool);
    prune(&mut pool, now);
    let mut best: Option<(&String, &AiNodeEntry)> = None;
    for (id, e) in pool.iter() {
        if e.iroh_node_id.is_none() || e.throttled {
            continue;
        }
        // шарды не принимают Infer напрямую: shard-ready ноды и ноды
        // с диапазонами alias@a..b исключаем (диапазон = нода-шард)
        if e.shard_ready || e.models.iter().any(|m| m.contains('@')) {
            continue;
        }
        // GPU обязателен только для «слепого» выбора; нода, рекламирующая
        // запрошенную модель (исполнитель или шлюз конвейера), подходит всегда
        if q.model.is_none() && !e.has_gpu {
            continue;
        }
        if let Some(m) = &q.model {
            if !e.models.iter().any(|x| x == m) {
                continue;
            }
        }
        if let Some(min) = q.min_vram_mb {
            if e.vram_free_mb < min {
                continue;
            }
        }
        let better = match &best {
            None => true,
            Some((_, b)) => {
                e.vram_free_mb > b.vram_free_mb
                    || (e.vram_free_mb == b.vram_free_mb && e.tflops_fp16 > b.tflops_fp16)
            }
        };
        if better {
            best = Some((id, e));
        }
    }
    let Some((id, e)) = best else {
        return Err((StatusCode::NOT_FOUND, "нет подходящих AI-нод".into()));
    };
    Ok(Json(serde_json::json!({
        "nodeId": id,
        "irohNodeId": e.iroh_node_id,
        "models": e.models,
        "vramFreeMb": e.vram_free_mb,
        "tflopsFp16": e.tflops_fp16,
        "cudaCapability": e.cuda_capability,
    })))
}

/// Ноды, готовые к авто-разрезке слоёв (--shard-auto с моделью ?model=).
/// Отсортированы по свободному VRAM (шлюз режет слои пропорционально).
pub async fn ai_shard_nodes(
    State(state): State<AppState>,
    Query(q): Query<PickQuery>,
) -> Json<serde_json::Value> {
    let now = now_unix();
    let mut pool = crate::lk(&state.ai_pool);
    prune(&mut pool, now);
    let mut list: Vec<(&String, &AiNodeEntry)> = pool
        .iter()
        .filter(|(_, e)| {
            e.shard_ready
                && !e.throttled
                && e.iroh_node_id.is_some()
                // шард рекламирует alias@a..b (голый alias только у полных нод),
                // поэтому матчим и точное имя, и префикс "alias@"
                && q.model
                    .as_ref()
                    .map(|m| {
                        let pref = format!("{m}@");
                        e.models.iter().any(|x| x == m || x.starts_with(&pref))
                    })
                    .unwrap_or(true)
                && q.min_vram_mb.map(|min| e.vram_free_mb >= min).unwrap_or(true)
        })
        .collect();
    list.sort_by(|a, b| b.1.vram_free_mb.cmp(&a.1.vram_free_mb));
    Json(serde_json::json!(list
        .into_iter()
        .map(|(id, e)| serde_json::json!({
            "nodeId": id,
            "irohNodeId": e.iroh_node_id,
            "vramFreeMb": e.vram_free_mb,
            "tflopsFp16": e.tflops_fp16,
        }))
        .collect::<Vec<_>>()))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AiNodeOut {
    /// STH-адрес ноды
    node: String,
    /// iroh NodeId воркера (ai://-адрес; None у чистой телеметрии) —
    /// нужен внешним провайдерам (ntfry-ai) для прямого подключения
    iroh_node_id: Option<String>,
    /// версия бинарника (None у старых нод)
    version: Option<String>,
    /// true = AI-воркер (принимает инференс по ai://), false = телеметрия клиента
    worker: bool,
    gpu: bool,
    vram_free_mb: u64,
    vram_total_mb: u64,
    tflops_fp16: f64,
    models: Vec<String>,
    shard_ready: bool,
    throttled: bool,
    last_seen: u64,
    /// метрики конвейера шлюза {ttftMs, tokPerSec, requests, batch}
    pipe: Option<serde_json::Value>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PipelineOut {
    /// базовый alias модели (без @a..b)
    model: String,
    /// сколько шардовых диапазонов сейчас загружено
    shards: u64,
    /// сами диапазоны слоёв: ["0..16", "16..32", …]
    ranges: Vec<String>,
    /// нод с ПОЛНОЙ моделью (не шардированной)
    full_nodes: u64,
    /// живой tok/s: сумма по шлюзам модели (0 = нет активной генерации)
    tok_per_sec: f64,
    /// шлюзов конвейера, отдающих pipe-метрики по этой модели
    gateways: u64,
    /// мин. цена среди обслуживающих нод, STH за 1 млн токенов (None = бесплатно)
    price_per_mtok: Option<u64>,
    /// continuous batching: занятые слоты / суммарный лимит по шлюзам
    slots: u64,
    max_slots: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AiStatsOut {
    active_nodes: u64,
    gpu_nodes: u64,
    total_vram_gb: f64,
    total_vram_free_gb: f64,
    total_tflops_fp16: f64,
    total_threads: u64,
    total_ram_gb: f64,
    total_ram_free_gb: f64,
    /// alias → число нод с этой моделью (шарды считаются по базовому имени)
    models: std::collections::HashMap<String, u64>,
    /// нод, ждущих LoadShard (--shard-auto)
    shard_ready_nodes: u64,
    /// загруженных шардовых диапазонов (alias@a..b) активные конвейеры
    active_shards: u64,
    /// активные конвейеры по моделям: шарды, диапазоны слоёв, полные ноды
    pipelines: Vec<PipelineOut>,
    /// список активных нод с версиями (для UI, до 200 последних)
    nodes: Vec<AiNodeOut>,
    /// каталог опубликованных моделей: alias → тикет (publish-model --alias)
    model_tickets: Vec<ModelTicketOut>,
    updated_at: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelTicketOut {
    alias: String,
    ticket: String,
    registered_at: u64,
}

fn round1(v: f64) -> f64 {
    (v * 10.0).round() / 10.0
}

pub async fn ai_stats(State(state): State<AppState>) -> Json<AiStatsOut> {
    let now = now_unix();
    let mut pool = crate::lk(&state.ai_pool);
    prune(&mut pool, now);
    let mut out = AiStatsOut {
        active_nodes: pool.len() as u64,
        gpu_nodes: 0,
        total_vram_gb: 0.0,
        total_vram_free_gb: 0.0,
        total_tflops_fp16: 0.0,
        total_threads: 0,
        total_ram_gb: 0.0,
        total_ram_free_gb: 0.0,
        models: std::collections::HashMap::new(),
        shard_ready_nodes: 0,
        active_shards: 0,
        pipelines: Vec::new(),
        nodes: Vec::new(),
        model_tickets: Vec::new(),
        updated_at: now,
    };
    // каталог опубликованных моделей (для UI: alias + команда скачивания);
    // мёртвые alias'ы (источник молчит > суток) отсеиваются здесь же
    {
        let mut map = crate::lk(tickets());
        prune_tickets(&mut map, now);
        out.model_tickets = map
            .iter()
            .map(|(a, (t, ts))| ModelTicketOut {
                alias: a.clone(),
                ticket: t.clone(),
                registered_at: *ts,
            })
            .collect();
        out.model_tickets.sort_by(|a, b| b.registered_at.cmp(&a.registered_at));
    }
    // model → агрегат маркетплейса (шарды, диапазоны, ноды, tok/s, цена)
    #[derive(Default)]
    struct PAgg {
        shards: u64,
        ranges: Vec<String>,
        full_nodes: u64,
        tok_per_sec: f64,
        gateways: u64,
        min_price: Option<u64>,
        slots: u64,
        max_slots: u64,
    }
    let mut pmap: std::collections::BTreeMap<String, PAgg> = std::collections::BTreeMap::new();
    for (id, e) in pool.iter() {
        out.nodes.push(AiNodeOut {
            node: id.clone(),
            iroh_node_id: e.iroh_node_id.clone(),
            version: e.version.clone(),
            worker: e.iroh_node_id.is_some(),
            gpu: e.has_gpu,
            vram_free_mb: e.vram_free_mb,
            vram_total_mb: e.vram_total_mb,
            tflops_fp16: e.tflops_fp16,
            models: e.models.clone(),
            shard_ready: e.shard_ready,
            throttled: e.throttled,
            last_seen: e.last_seen,
            pipe: e.pipe.clone(),
        });
        if e.shard_ready {
            out.shard_ready_nodes += 1;
        }
        for m in &e.models {
            if let Some((base, range)) = m.split_once('@') {
                out.active_shards += 1;
                *out.models.entry(base.to_string()).or_insert(0) += 1;
                let ent = pmap.entry(base.to_string()).or_default();
                ent.shards += 1;
                ent.ranges.push(range.to_string());
            } else {
                *out.models.entry(m.clone()).or_insert(0) += 1;
                let ent = pmap.entry(m.clone()).or_default();
                // шард-ноды рекламируют базовый alias для сборки конвейера —
                // «полными» исполнителями их не считаем
                if !e.shard_ready {
                    ent.full_nodes += 1;
                    // маркетплейс: цена и живые pipe-метрики обслуживающих нод
                    if e.price_per_mtok > 0 {
                        ent.min_price = Some(match ent.min_price {
                            Some(p) => p.min(e.price_per_mtok),
                            None => e.price_per_mtok,
                        });
                    }
                    if let Some(p) = &e.pipe {
                        ent.gateways += 1;
                        ent.tok_per_sec += p["tokPerSec"].as_f64().unwrap_or(0.0);
                        ent.slots += p["slots"].as_u64().unwrap_or(0);
                        ent.max_slots += p["maxSlots"].as_u64().unwrap_or(0);
                    }
                }
            }
        }
        if e.has_gpu {
            out.gpu_nodes += 1;
        }
        out.total_vram_gb += e.vram_total_mb as f64 / 1024.0;
        out.total_vram_free_gb += e.vram_free_mb as f64 / 1024.0;
        out.total_tflops_fp16 += e.tflops_fp16;
        out.total_threads += e.threads as u64;
        out.total_ram_gb += e.ram_total_mb as f64 / 1024.0;
        out.total_ram_free_gb += e.ram_free_mb as f64 / 1024.0;
    }
    out.total_vram_gb = round1(out.total_vram_gb);
    out.total_vram_free_gb = round1(out.total_vram_free_gb);
    out.total_tflops_fp16 = round1(out.total_tflops_fp16);
    out.total_ram_gb = round1(out.total_ram_gb);
    out.total_ram_free_gb = round1(out.total_ram_free_gb);
    out.pipelines = pmap
        .into_iter()
        .map(|(model, mut a)| {
            // сортировка диапазонов по начальному слою: "0..16" < "16..32"
            a.ranges.sort_by_key(|r| {
                r.split_once("..")
                    .and_then(|(x, _)| x.trim().parse::<u64>().ok())
                    .unwrap_or(u64::MAX)
            });
            PipelineOut {
                model,
                shards: a.shards,
                ranges: a.ranges,
                full_nodes: a.full_nodes,
                tok_per_sec: round1(a.tok_per_sec),
                gateways: a.gateways,
                price_per_mtok: a.min_price,
                slots: a.slots,
                max_slots: a.max_slots,
            }
        })
        .collect();
    // свежие сверху, не более 200 нод в выдаче
    out.nodes.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
    out.nodes.truncate(200);
    Json(out)
}
