use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use augenmass_relay_proto::{ClientFrame, CloseCode, ReqId, ServerFrame};
use tokio::sync::{mpsc, oneshot, Mutex};

use crate::id::mint_run_id;

#[derive(Debug)]
pub enum ForwardReply {
    Response(augenmass_relay_proto::HttpResponseFrame),
    Error(augenmass_relay_proto::HttpErrorKind),
}

pub enum RunLookup {
    Active(Arc<Run>),
    Tombstoned,
    Missing,
}

pub struct RunRegistry {
    runs: Mutex<HashMap<String, Arc<Run>>>,
    tombstones: Mutex<HashMap<String, Instant>>,
    tombstone_ttl: Duration,
    max_tombstones: usize,
    max_runs: usize,
}

pub struct Run {
    pub id: String,
    pub expires_at: Instant,
    pub tx: mpsc::Sender<ServerFrame>,
    pending: Mutex<HashMap<ReqId, oneshot::Sender<ForwardReply>>>,
    inflight: AtomicUsize,
    next_req_id: AtomicU64,
    last_pong: Mutex<Instant>,
}

pub struct InflightGuard {
    run: Arc<Run>,
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        self.run.inflight.fetch_sub(1, Ordering::SeqCst);
    }
}

impl RunRegistry {
    pub fn new(tombstone_ttl: Duration, max_tombstones: usize, max_runs: usize) -> Self {
        Self {
            runs: Mutex::new(HashMap::new()),
            tombstones: Mutex::new(HashMap::new()),
            tombstone_ttl,
            max_tombstones,
            max_runs,
        }
    }

    pub async fn mint(&self, ttl: Duration) -> Option<(Arc<Run>, mpsc::Receiver<ServerFrame>)> {
        let (tx, rx) = mpsc::channel(64);
        let run = Arc::new(Run {
            id: mint_run_id(),
            expires_at: Instant::now() + ttl,
            tx,
            pending: Mutex::new(HashMap::new()),
            inflight: AtomicUsize::new(0),
            next_req_id: AtomicU64::new(1),
            last_pong: Mutex::new(Instant::now()),
        });
        let mut runs = self.runs.lock().await;
        if runs.len() >= self.max_runs {
            return None;
        }
        runs.insert(run.id.clone(), run.clone());
        Some((run, rx))
    }

    pub async fn lookup(&self, run_id: &str) -> RunLookup {
        if let Some(run) = self.runs.lock().await.get(run_id).cloned() {
            if Instant::now() < run.expires_at {
                return RunLookup::Active(run);
            }
            self.remove(run_id, CloseCode::Expired, "run expired").await;
            return RunLookup::Tombstoned;
        }
        self.evict_old_tombstones().await;
        if self.tombstones.lock().await.contains_key(run_id) {
            RunLookup::Tombstoned
        } else {
            RunLookup::Missing
        }
    }

    pub async fn remove(&self, run_id: &str, code: CloseCode, reason: &str) {
        let run = self.runs.lock().await.remove(run_id);
        if let Some(run) = run {
            let _ = run.tx.try_send(ServerFrame::Close {
                code,
                reason: reason.to_string(),
            });
            let mut tombstones = self.tombstones.lock().await;
            tombstones.insert(run_id.to_string(), Instant::now() + self.tombstone_ttl);
            while tombstones.len() > self.max_tombstones {
                if let Some(key) = tombstones
                    .iter()
                    .min_by_key(|(_, expires)| **expires)
                    .map(|(key, _)| key.clone())
                {
                    tombstones.remove(&key);
                } else {
                    break;
                }
            }
        }
    }

    pub async fn sweep_expired(&self) {
        let now = Instant::now();
        let expired = {
            let runs = self.runs.lock().await;
            runs.iter()
                .filter(|(_, run)| now >= run.expires_at)
                .map(|(id, _)| id.clone())
                .collect::<Vec<_>>()
        };
        for run_id in expired {
            self.remove(&run_id, CloseCode::Expired, "run expired")
                .await;
        }
        self.evict_old_tombstones().await;
    }

    async fn evict_old_tombstones(&self) {
        let now = Instant::now();
        self.tombstones
            .lock()
            .await
            .retain(|_, expires| *expires > now);
    }
}

impl Run {
    pub fn next_req_id(&self) -> ReqId {
        self.next_req_id.fetch_add(1, Ordering::SeqCst)
    }

    pub fn try_acquire(self: &Arc<Self>, max_inflight: usize) -> Option<InflightGuard> {
        let mut current = self.inflight.load(Ordering::SeqCst);
        loop {
            if current >= max_inflight {
                return None;
            }
            match self.inflight.compare_exchange(
                current,
                current + 1,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => return Some(InflightGuard { run: self.clone() }),
                Err(next) => current = next,
            }
        }
    }

    pub async fn register_pending(&self, req_id: ReqId) -> oneshot::Receiver<ForwardReply> {
        let (tx, rx) = oneshot::channel();
        self.pending.lock().await.insert(req_id, tx);
        rx
    }

    pub async fn remove_pending(&self, req_id: ReqId) {
        self.pending.lock().await.remove(&req_id);
    }

    pub async fn resolve_pending(&self, req_id: ReqId, reply: ForwardReply) {
        if let Some(tx) = self.pending.lock().await.remove(&req_id) {
            let _ = tx.send(reply);
        }
    }

    pub async fn note_pong(&self) {
        *self.last_pong.lock().await = Instant::now();
    }

    pub async fn age_since_pong(&self) -> Duration {
        Instant::now().saturating_duration_since(*self.last_pong.lock().await)
    }
}

impl From<ClientFrame> for ForwardReply {
    fn from(frame: ClientFrame) -> Self {
        match frame {
            ClientFrame::HttpResponse(response) => Self::Response(response),
            ClientFrame::HttpError { kind, .. } => Self::Error(kind),
            _ => Self::Error(augenmass_relay_proto::HttpErrorKind::ProtocolError),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn removed_run_is_tombstoned_then_evicted() {
        let registry = RunRegistry::new(Duration::from_millis(20), 8, 8);
        let (run, _rx) = registry.mint(Duration::from_secs(10)).await.unwrap();
        let id = run.id.clone();
        assert!(matches!(registry.lookup(&id).await, RunLookup::Active(_)));
        registry
            .remove(&id, CloseCode::ServerShutdown, "test")
            .await;
        assert!(matches!(registry.lookup(&id).await, RunLookup::Tombstoned));
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(matches!(registry.lookup(&id).await, RunLookup::Missing));
    }

    #[tokio::test]
    async fn max_runs_is_enforced() {
        let registry = RunRegistry::new(Duration::from_secs(1), 8, 1);
        assert!(registry.mint(Duration::from_secs(10)).await.is_some());
        assert!(registry.mint(Duration::from_secs(10)).await.is_none());
    }
}
