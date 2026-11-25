//! The in-memory job queue: one job runs, manual jobs go ahead of automatic
//! ones, and a target is never queued twice.
//!
//! The queue is not persisted. A scan lost to a restart is picked up again
//! when the agent resends its list of devices ([`crate::proto::Request::Known`]).

use crate::proto::{JobKind, QueuedJob, Refusal, StartReq};
use crate::target::{self, Target};

/// Most jobs waiting at once.
pub const MAX_QUEUED: usize = 4096;

/// A scan job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Job {
    /// Set by [`Queue::push`].
    pub id: u64,
    pub kind: JobKind,
    /// The target as given.
    pub target: String,
    /// The target parsed.
    pub parsed: Target,
    /// The device's MAC, for device jobs.
    pub mac: Option<String>,
    pub auto: bool,
    pub public_ok: bool,
    /// Scan excluded addresses of a range anyway.
    pub include_excluded: bool,
}

impl Job {
    /// A job for `req` (id 0 until queued). MACs are stored lowercase.
    ///
    /// # Errors
    /// [`Refusal::Invalid`] when the target does not parse, or a device job
    /// is given more than one address.
    pub fn new(req: &StartReq) -> Result<Job, Refusal> {
        let parsed = target::parse(&req.target).map_err(Refusal::Invalid)?;
        if req.kind == JobKind::Device && !matches!(parsed, Target::One(_)) {
            return Err(Refusal::Invalid(
                "a device scan takes one address".to_string(),
            ));
        }
        Ok(Job {
            id: 0,
            kind: req.kind,
            target: req.target.trim().to_string(),
            parsed,
            mac: req.mac.as_deref().map(str::to_ascii_lowercase),
            auto: req.auto,
            public_ok: req.public_ok,
            include_excluded: req.include_excluded,
        })
    }

    /// Whether `self` and `other` scan the same thing: the same device MAC,
    /// or else the same target.
    fn same_target(&self, other: &Job) -> bool {
        if self.kind != other.kind {
            return false;
        }
        match (&self.mac, &other.mac) {
            (Some(a), Some(b)) if self.kind == JobKind::Device => a == b,
            _ => self.parsed == other.parsed && self.mac == other.mac,
        }
    }

    fn view(&self) -> QueuedJob {
        QueuedJob {
            job_id: self.id,
            kind: self.kind,
            target: self.target.clone(),
        }
    }
}

/// Waiting jobs plus the one running.
#[derive(Debug, Default)]
pub struct Queue {
    waiting: Vec<Job>,
    running: Option<Job>,
    last_id: u64,
}

impl Queue {
    /// Queue `job`. Manual jobs go after other manual jobs but ahead of every
    /// automatic one. A target already queued or running gets that job's id
    /// back; a manual request for a target with an automatic job waiting
    /// moves that job up as a manual one.
    ///
    /// A new job keeps its `id` (the daemon passes its store id); id 0 gets
    /// the next id of the queue's own counter.
    ///
    /// # Errors
    /// [`Refusal::Invalid`] when [`MAX_QUEUED`] jobs are already waiting.
    pub fn push(&mut self, mut job: Job) -> Result<u64, Refusal> {
        if let Some(r) = self.running.as_ref().filter(|r| r.same_target(&job)) {
            return Ok(r.id);
        }
        if let Some(i) = self.waiting.iter().position(|w| w.same_target(&job)) {
            let id = self.waiting[i].id;
            if self.waiting[i].auto && !job.auto {
                let mut w = self.waiting.remove(i);
                w.auto = false;
                self.insert(w);
            }
            return Ok(id);
        }
        if self.is_full() {
            return Err(Refusal::Invalid("too many scans are queued".to_string()));
        }
        if job.id == 0 {
            self.last_id += 1;
            job.id = self.last_id;
        }
        let id = job.id;
        self.insert(job);
        Ok(id)
    }

    /// The running or waiting job for the same target as `job`.
    #[must_use]
    pub fn find(&self, job: &Job) -> Option<&Job> {
        self.running
            .iter()
            .chain(&self.waiting)
            .find(|j| j.same_target(job))
    }

    /// Whether [`MAX_QUEUED`] jobs wait.
    #[must_use]
    pub fn is_full(&self) -> bool {
        self.waiting.len() >= MAX_QUEUED
    }

    fn insert(&mut self, job: Job) {
        let at = if job.auto {
            self.waiting.len()
        } else {
            self.waiting
                .iter()
                .position(|w| w.auto)
                .unwrap_or(self.waiting.len())
        };
        self.waiting.insert(at, job);
    }

    /// Take the next job and mark it running. `None` while a job runs or
    /// nothing waits.
    // Named by the plan; a queue that holds a job running is not an iterator.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Option<Job> {
        if self.running.is_some() || self.waiting.is_empty() {
            return None;
        }
        let job = self.waiting.remove(0);
        self.running = Some(job.clone());
        Some(job)
    }

    /// The running job `id` has ended.
    pub fn finish(&mut self, id: u64) {
        if self.running.as_ref().is_some_and(|r| r.id == id) {
            self.running = None;
        }
    }

    /// The running job's id.
    #[must_use]
    pub fn running(&self) -> Option<u64> {
        self.running.as_ref().map(|r| r.id)
    }

    /// Remove waiting job `id`, returning it.
    pub fn take(&mut self, id: u64) -> Option<Job> {
        let i = self.waiting.iter().position(|w| w.id == id)?;
        Some(self.waiting.remove(i))
    }

    /// Remove waiting job `id`; whether it was waiting.
    pub fn cancel(&mut self, id: u64) -> bool {
        self.take(id).is_some()
    }

    /// Waiting jobs, in the order they will run.
    #[must_use]
    pub fn view(&self) -> Vec<QueuedJob> {
        self.waiting.iter().map(Job::view).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn job(target: &str, mac: Option<&str>, auto: bool) -> Job {
        Job::new(&StartReq {
            target: target.into(),
            kind: JobKind::Device,
            auto,
            mac: mac.map(Into::into),
            public_ok: false,
            confirm: false,
            include_excluded: false,
        })
        .unwrap()
    }

    fn order(q: &Queue) -> Vec<String> {
        q.view().into_iter().map(|j| j.target).collect()
    }

    #[test]
    fn manual_jobs_go_ahead_of_auto_in_fifo_order() {
        let mut q = Queue::default();
        q.push(job("10.0.0.1", Some("aa:00:00:00:00:01"), true))
            .unwrap();
        q.push(job("10.0.0.2", None, false)).unwrap();
        q.push(job("10.0.0.3", Some("aa:00:00:00:00:03"), true))
            .unwrap();
        q.push(job("10.0.0.4", None, false)).unwrap();
        assert_eq!(order(&q), ["10.0.0.2", "10.0.0.4", "10.0.0.1", "10.0.0.3"]);
    }

    #[test]
    fn same_target_gets_the_same_id() {
        let mut q = Queue::default();
        let a = q
            .push(job("10.0.0.1", Some("AA:00:00:00:00:01"), true))
            .unwrap();
        // Same MAC at a new address is the same device.
        let b = q
            .push(job("10.0.0.9", Some("aa:00:00:00:00:01"), true))
            .unwrap();
        assert_eq!(a, b);
        let c = q.push(job("10.0.0.1", None, false)).unwrap();
        assert_ne!(a, c);
        assert_eq!(q.push(job("10.0.0.1", None, false)).unwrap(), c);
        assert_eq!(q.view().len(), 2);
    }

    #[test]
    fn running_target_gets_its_id() {
        let mut q = Queue::default();
        let a = q.push(job("10.0.0.1", None, false)).unwrap();
        assert_eq!(q.next().unwrap().id, a);
        assert_eq!(q.running(), Some(a));
        assert_eq!(q.push(job("10.0.0.1", None, false)).unwrap(), a);
        assert!(q.view().is_empty());
        q.finish(a);
        assert_eq!(q.running(), None);
        assert_ne!(q.push(job("10.0.0.1", None, false)).unwrap(), a);
    }

    #[test]
    fn manual_request_promotes_a_waiting_auto_job() {
        let mut q = Queue::default();
        q.push(job("10.0.0.1", Some("aa:00:00:00:00:01"), true))
            .unwrap();
        let b = q
            .push(job("10.0.0.2", Some("aa:00:00:00:00:02"), true))
            .unwrap();
        assert_eq!(
            q.push(job("10.0.0.2", Some("aa:00:00:00:00:02"), false))
                .unwrap(),
            b
        );
        assert_eq!(order(&q), ["10.0.0.2", "10.0.0.1"]);
        assert!(!q.next().unwrap().auto);
    }

    #[test]
    fn one_job_runs_at_a_time() {
        let mut q = Queue::default();
        let a = q.push(job("10.0.0.1", None, false)).unwrap();
        let b = q.push(job("10.0.0.2", None, false)).unwrap();
        assert_eq!(q.next().unwrap().id, a);
        assert!(q.next().is_none());
        q.finish(a);
        assert_eq!(q.next().unwrap().id, b);
    }

    #[test]
    fn cancel_removes_only_waiting_jobs() {
        let mut q = Queue::default();
        let a = q.push(job("10.0.0.1", None, false)).unwrap();
        let b = q.push(job("10.0.0.2", None, false)).unwrap();
        q.next();
        assert!(
            !q.cancel(a),
            "running jobs are cancelled by token, not here"
        );
        assert!(q.cancel(b));
        assert!(!q.cancel(b));
        assert!(q.view().is_empty());
    }

    #[test]
    fn given_ids_are_kept_and_find_sees_running_and_waiting() {
        let mut q = Queue::default();
        let mut a = job("10.0.0.1", None, false);
        a.id = 41;
        let mut b = job("10.0.0.2", None, true);
        b.id = 42;
        assert_eq!(q.push(a.clone()).unwrap(), 41);
        assert_eq!(q.push(b.clone()).unwrap(), 42);
        assert!(q.find(&job("10.0.0.3", None, false)).is_none());
        q.next();
        assert_eq!(q.find(&a).unwrap().id, 41);
        assert_eq!(q.find(&b).unwrap().id, 42);
    }

    #[test]
    fn queue_is_bounded() {
        let mut q = Queue::default();
        for n in 0..MAX_QUEUED {
            let ip = std::net::Ipv4Addr::from(0x0a00_0000 + u32::try_from(n).unwrap());
            q.push(job(&ip.to_string(), None, true)).unwrap();
        }
        assert!(q.is_full());
        assert!(matches!(
            q.push(job("192.168.0.1", None, false)),
            Err(Refusal::Invalid(_))
        ));
    }

    #[test]
    fn device_jobs_take_one_address() {
        let req = StartReq {
            target: "10.0.0.0/30".into(),
            kind: JobKind::Device,
            auto: false,
            mac: None,
            public_ok: false,
            confirm: false,
            include_excluded: false,
        };
        assert!(matches!(Job::new(&req), Err(Refusal::Invalid(_))));
        let req = StartReq {
            target: "nonsense".into(),
            kind: JobKind::Range,
            ..req
        };
        assert!(matches!(Job::new(&req), Err(Refusal::Invalid(_))));
    }
}
