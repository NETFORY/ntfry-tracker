// Диагностика живости трекера (v1.7.2).
//
// Причина появления модуля: трекер раз в несколько часов «висел в памяти» —
// процесс жив, порт не отвечает, в логах НИ ОДНОЙ строки. Разбор кода дал
// несколько классов таких отказов (fsync sled в request-path, отравленный
// Mutex после паники, вечно висящий keep-alive/запрос), и ни один из них не
// оставлял следа в логе. Здесь собрано всё, что нужно, чтобы следующий отказ
// был объяснён строкой в логе: perf-снимок процесса, лог паник и вотчдог,
// который сам стучится на 127.0.0.1:<port>/health и печатает отчёт.
//
// Процесс НЕ завершается вотчдогом (по требованию оператора) только логи.

use std::io::{Read, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// unix-время последнего «тика» async-задачи: если оно перестало расти,
/// значит залип сам рантайм tokio (а не только HTTP-слой).
pub static HEARTBEAT: AtomicU64 = AtomicU64::new(0);
/// сколько паник поймал хук (паника внутри обработчика раньше уходила в /dev/null).
pub static PANICS: AtomicU64 = AtomicU64::new(0);

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Паники обработчиков пишем в лог через tracing (раньше их не было видно).
pub fn install_panic_hook() {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        PANICS.fetch_add(1, Ordering::Relaxed);
        let msg = info
            .payload()
            .downcast_ref::<&str>()
            .map(|s| s.to_string())
            .or_else(|| info.payload().downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "<no message>".to_string());
        let loc = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_else(|| "<unknown>".into());
        tracing::error!("PANIC at {loc}: {msg} (всего паник: {})", PANICS.load(Ordering::Relaxed));
        prev(info);
    }));
}

/// Число открытых файловых дескрипторов процесса (утечка сокетов = порт «висит»).
pub fn open_fds() -> usize {
    std::fs::read_dir("/proc/self/fd").map(|d| d.count()).unwrap_or(0)
}

/// Лимит на открытые файлы (soft, hard) из /proc/self/limits.
pub fn nofile_limit() -> (u64, u64) {
    let Ok(txt) = std::fs::read_to_string("/proc/self/limits") else { return (0, 0) };
    for line in txt.lines() {
        if !line.starts_with("Max open files") {
            continue;
        }
        let cols: Vec<&str> = line.split_whitespace().collect();
        let n = cols.len();
        if n >= 4 {
            let soft = cols[n - 3].parse().unwrap_or(0);
            let hard = cols[n - 2].parse().unwrap_or(0);
            return (soft, hard);
        }
    }
    (0, 0)
}

/// Resident set size процесса, МБ.
pub fn rss_mb() -> u64 {
    let Ok(txt) = std::fs::read_to_string("/proc/self/statm") else { return 0 };
    let pages: u64 = txt.split_whitespace().nth(1).and_then(|v| v.parse().ok()).unwrap_or(0);
    pages * 4096 / 1_048_576
}

/// Число потоков процесса (рост = утечка blocking-задач tokio).
pub fn threads() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|t| {
            t.lines()
                .find(|l| l.starts_with("Threads:"))
                .and_then(|l| l.split_whitespace().nth(1).and_then(|v| v.parse().ok()))
        })
        .unwrap_or(0)
}

/// Компактный снимок процесса для лога.
pub fn proc_report() -> String {
    let (soft, hard) = nofile_limit();
    format!(
        "fd={} (limit {}/{}) rss={}MB threads={} panics={}",
        open_fds(),
        soft,
        hard,
        rss_mb(),
        threads(),
        PANICS.load(Ordering::Relaxed)
    )
}

/// Возраст heartbeat async-задачи в секундах (u64::MAX задача ещё не стартовала).
pub fn heartbeat_age() -> u64 {
    let hb = HEARTBEAT.load(Ordering::Relaxed);
    if hb == 0 {
        return u64::MAX;
    }
    now_unix().saturating_sub(hb)
}

/// Синхронная проба своего же HTTP-порта (без tokio и без reqwest/ureq, чтобы
/// вотчдог не зависел от занятого рантайма). true пришёл ответ «200 OK».
pub fn probe_health(port: u16) -> bool {
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    let Ok(mut sock) = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)) else {
        return false;
    };
    let _ = sock.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = sock.set_write_timeout(Some(Duration::from_secs(5)));
    if sock.write_all(b"GET /health HTTP/1.0\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n").is_err() {
        return false;
    }
    let mut buf = [0u8; 256];
    match sock.read(&mut buf) {
        Ok(n) if n > 0 => String::from_utf8_lossy(&buf[..n]).contains(" 200 "),
        _ => false,
    }
}
