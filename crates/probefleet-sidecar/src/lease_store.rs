//! Cross-invocation persistence for [`crate::lease_cache`].
//!
//! [`crate::lease_cache`] is pure logic with an injected clock and deliberately
//! no persistence. This module is the persistence layer layered *on top* of it:
//! a small JSON file under `$XDG_RUNTIME_DIR/probe-rs-fleet/leases.json` that
//! lets successive `probe-rs` invocations reuse one lease instead of leasing and
//! releasing on every command (architecture §6.6). The validity/expiry
//! judgement itself is still `lease_cache`'s — a loaded record is fed through
//! [`LeaseCache::get`] so the refresh-margin semantics have exactly one
//! implementation.
//!
//! # Decision 1 — the cache key
//!
//! The **file** is keyed on `(coordinator, token fingerprint, selector
//! fingerprint)`. The **in-memory [`LeaseCache`]** is keyed on the real
//! [`SubjectKey`], recovered from the stored record.
//!
//! The sidecar never sees its subject before it leases — the subject is
//! resolved coordinator-side from the bearer token — so a *pre-lease* lookup
//! cannot use a `SubjectKey`. What the sidecar always has is the coordinator URL
//! and the bearer token, hence:
//!
//! * `token_fp` = the first 16 hex characters of `SHA-256(bearer token)`. The
//!   token itself is **never** written to disk.
//! * `selector` = [`crate::lease_cache::fingerprint`], reused verbatim rather
//!   than a second fingerprint of our own (that module explains why it must stay
//!   distinct from `Constraint`'s round-trippable `Display`).
//! * `coordinator` is part of the key so two fleets never share an entry.
//!
//! Keying on the token rather than on "a previous grant's holder" is the
//! conservative direction: a re-login mints a new token for the same human, so
//! that becomes a *miss* (one extra lease) instead of a risk of handing a lease
//! across identities after a token is re-issued.
//!
//! # Decision 2 — release policy
//!
//! TTL-driven, with two guards. A shareable lease is **not** released at the end
//! of an invocation (releasing it every time is exactly what would make the
//! cache never hit) — including on the Ctrl-C arm. It keeps riding
//! `duration_secs: 0`, i.e. the operator's `Policy::default_ttl_secs`: the
//! sidecar still never picks a TTL of its own. `fleet ctl release` frees a board
//! immediately; otherwise it returns after one policy TTL, which is the
//! already-documented worst case for a `SIGKILL`ed sidecar.
//!
//! * **Guard A — CI never caches.** A grant whose `holder.kind` is not
//!   [`SubjectKind::User`] (a `Workload` or a `Node`) is not stored and is
//!   released at exit exactly as before, so a finished CI job never strands a
//!   board for a policy TTL.
//! * **Guard B — an opt-out.** [`crate::selector::env::NO_LEASE_CACHE`] disables
//!   the store entirely, restoring lease-and-release-per-invocation.
//!
//! The delegated path never caches: the lease is not ours (architecture §6.5).
//!
//! # Decision 3 — the cached grant's token is not reusable
//!
//! A hit skips `Lease` and goes straight to `OpenChannel`; the data-plane
//! credentials are the **fresh** ones from `ChannelOpened`, as on the cold
//! path — its `token` (the per-channel capability the node verifies) and its
//! `serve_token` (the lease-scoped secret `probe-rs serve` accepts). A record
//! therefore stores no token at all: not the bearer token, not the
//! grant's capability token. A [`LeaseGrant`] reconstructed for
//! [`LeaseCache::insert`] carries an empty `token`, which is sound precisely
//! because the hit path never reads it.
//!
//! # Decision 4 — a stale hit degrades, never errors
//!
//! A hit is revalidated with a short `Extend` probe
//! ([`crate::transport::CoordSession::revalidate_lease`]) before any work
//! starts. A refusal or an inconclusive reply drops the entry and falls through
//! to a fresh `Lease`; the inconclusive case sends a best-effort `Release`
//! first, because a fresh `Lease` under an `Id` selector would otherwise be
//! queued behind our own still-live hold.
//!
//! # Decision 5 — the per-record use-lock is the concurrency interlock
//!
//! Today two concurrent invocations under one selector cannot both drive a
//! board: the second one's `Lease` is answered `Queued`, which surfaces as
//! `board contended`. A cache that let both skip `Lease` would remove that
//! interlock — the coordinator caps neither channels per lease nor sessions per
//! board — and two `probe-rs serve` processes would end up on one probe. So the
//! store carries two *distinct* locks:
//!
//! | lock | scope | held for |
//! |---|---|---|
//! | `leases.lock` | the whole file | the few ms of a read-modify-write in [`LeaseStore::save`] |
//! | `use-<h>.lock` | one record | the entire invocation |
//!
//! A hit is only taken if `flock(use-<h>.lock, LOCK_EX | LOCK_NB)` succeeds.
//! `EWOULDBLOCK` means another live invocation holds that record, so we do
//! **not** hit and fall through to a fresh `Lease` — reproducing today's
//! `Queued` → `board contended` behaviour exactly, rather than inventing a new
//! error.
//!
//! **Holding the lock is what makes a slot ours to write.** An invocation that
//! failed to take it leases cold and must then leave the store completely
//! alone: the record on disk belongs to the invocation that *is* holding the
//! lock, and is one it deliberately intends to keep. Deleting it would leave a
//! board held with nothing naming it — unreusable, and unreleased until the
//! policy TTL. So `forget` / `touch_expiry` outside `acquire_lease` are gated
//! on `Acquired::owns_slot`, and a `forget` always happens *before* the guard
//! is dropped, never after.
//!
//! `flock` is used instead of a pid + timestamp marker because the kernel gives
//! us liveness for free, with no staleness window to tune:
//!
//! 1. Rust's `OpenOptions` sets `O_CLOEXEC`, so the exec'd probe-rs child does
//!    not inherit the lock — its lifetime is exactly the sidecar's.
//! 2. The kernel drops the lock when the holder dies, `SIGKILL` included, so a
//!    killed sidecar cannot wedge the cache.
//! 3. Two separate `open()`s conflict within one process, so contention is
//!    testable without spawning helper binaries.
//!
//! One caveat follows from (1): a lock lives on the *open file description*,
//! and `O_CLOEXEC` is cleared at `exec`, not at `fork`. So between a `fork()`
//! and the matching `exec()` a child transiently pins whatever locks the parent
//! held, and a re-acquire in that window gets `EWOULDBLOCK`. It costs nothing
//! here — the sidecar forks exactly once, for the probe-rs child, and the next
//! invocation is a different process arriving later — but it is why the
//! use-lock unit test retries instead of asserting on the first attempt.
//!
//! **Lock ordering.** A use-lock is only ever acquired *outside* a `save`, and
//! `save` never touches a use-lock. Keep it that way: taking them in both orders
//! is the one way to deadlock this design. Lock files are tiny, live in the
//! runtime directory, and are reaped by the OS at logout, so nothing cleans them
//! up.
//!
//! # Deliberately out of scope
//!
//! * **The cold-start race.** Two invocations starting with an empty store both
//!   send `Lease`, and under an `Id` selector the loser is queued. The file lock
//!   prevents file corruption, not that; cross-invocation deduplication of a
//!   cold start belongs with the scheduler-queue work (#384).
//! * **A coordinator boot id.** Lease ids restart at 1 on every coordinator
//!   boot and nothing on the wire identifies a boot, so a persisted `LeaseId`
//!   can name a different lease after a restart. Rather than document the
//!   window, [`crate::open_channel_verified`] closes it by decoding the returned
//!   channel token and comparing its `board` with the record's. Adding a boot id
//!   to `Welcome` would be the systemic fix and is a `fleet-wire` protocol
//!   change; noted as a follow-up.

#[cfg(unix)]
mod unix_imp {
    use std::collections::BTreeMap;
    use std::fs::{File, OpenOptions};
    use std::io::Write as _;
    use std::path::{Path, PathBuf};

    use serde::{Deserialize, Serialize};
    use sha2::{Digest as _, Sha256};

    use fleet_proto::ids::{BoardRef, NodeId, SubjectKey, SubjectKind};
    use fleet_proto::lease::{Constraint, LeaseGrant};
    use fleet_proto::LeaseId;

    use crate::lease_cache::{fingerprint, CachedLease, LeaseCache};
    use crate::selector::EnvSource;

    /// On-disk format version. A file carrying anything else is treated as
    /// empty and overwritten — a cache is never worth an error.
    ///
    /// 1 → 2: the `agent` field of a [`Record`] is spelled `node`, following
    /// the fleet-wide `AgentId` → `NodeId` rename. A version-1 file would fail
    /// to deserialize anyway (the field is not optional); bumping makes the
    /// miss deliberate and quiet rather than a "corrupt store" debug line.
    ///
    /// 2 → 3: identity moved to forgs. A record's `holder` is the new
    /// [`SubjectKey`] shape (optional namespace, no org) and org ids are
    /// namespace ULIDs, so a version-2 record names a subject and board no
    /// v12 coordinator knows. Dropping them quietly is the honest outcome.
    const FORMAT_VERSION: u32 = 3;

    /// The runtime sub-directory everything lives in.
    const DIR_NAME: &str = "probe-rs-fleet";

    /// The store file, inside [`DIR_NAME`].
    const FILE_NAME: &str = "leases.json";

    /// The whole-file lock taken for a read-modify-write (see Decision 5).
    const FILE_LOCK_NAME: &str = "leases.lock";

    /// One persisted lease, minus anything secret (Decision 3).
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct Record {
        /// Coordinator base URL, part of the file key.
        pub coordinator: String,
        /// `SHA-256(bearer token)`, truncated — never the token itself.
        pub token_fp: String,
        /// [`crate::lease_cache::fingerprint`] of the selector.
        pub selector: String,
        /// The board the lease is on. Cross-checked against the channel token
        /// on a hit, so a coordinator restart cannot alias lease ids.
        pub board: BoardRef,
        /// The node hosting the board.
        pub node: NodeId,
        /// The lease itself.
        pub lease: LeaseId,
        /// The grant's holder, as its stable [`SubjectKey`].
        pub holder: SubjectKey,
        /// Expiry, epoch seconds, as last reported by the coordinator.
        pub expires: u64,
        /// The refresh margin the entry was judged with.
        pub refresh_margin_secs: u64,
    }

    impl Record {
        /// The record's identity within the file.
        fn key(&self) -> RecordKey {
            RecordKey {
                coordinator: self.coordinator.clone(),
                token_fp: self.token_fp.clone(),
                selector: self.selector.clone(),
            }
        }

        /// Rebuild a [`LeaseGrant`] for [`LeaseCache`], with an **empty** token:
        /// the hit path never reads it (Decision 3).
        #[must_use]
        pub fn grant(&self) -> LeaseGrant {
            LeaseGrant {
                lease: self.lease,
                board: self.board.clone(),
                node: self.node.clone(),
                holder: self.holder.clone(),
                expires: self.expires,
                token: Vec::new(),
            }
        }
    }

    /// The file key: `(coordinator, token fingerprint, selector fingerprint)`.
    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
    struct RecordKey {
        coordinator: String,
        token_fp: String,
        selector: String,
    }

    impl RecordKey {
        /// A short, filesystem-safe digest of the key, for the use-lock's name.
        fn digest(&self) -> String {
            let mut hasher = Sha256::new();
            hasher.update(self.coordinator.as_bytes());
            hasher.update([0]);
            hasher.update(self.token_fp.as_bytes());
            hasher.update([0]);
            hasher.update(self.selector.as_bytes());
            hex16(&hasher.finalize())
        }
    }

    /// The serialized file.
    #[derive(Debug, Default, Serialize, Deserialize)]
    struct FileBody {
        version: u32,
        #[serde(default)]
        records: Vec<Record>,
    }

    /// What [`crate::hold_and_run`] should do with the lease on the way out.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Disposition {
        /// Release the lease at exit, as the sidecar always did: the lease is
        /// not shareable (CI, opt-out, no store, or another live invocation
        /// owns the cache slot).
        Release,
        /// Keep the lease for the next invocation; it is recorded in the store
        /// and expires on the operator's TTL if nothing picks it up.
        Keep,
    }

    /// An RAII holder for a record's use-lock (Decision 5). Held for the whole
    /// invocation; dropping it releases the slot, and so does dying.
    #[derive(Debug)]
    pub struct UseGuard {
        _file: File,
    }

    /// Persistent, cross-invocation storage for [`LeaseCache`].
    #[derive(Debug)]
    pub struct LeaseStore {
        dir: PathBuf,
        path: PathBuf,
        /// Records as last read from disk, keyed for lookup.
        records: BTreeMap<String, Record>,
        /// Records this process wants written on the next [`LeaseStore::save`].
        pending: BTreeMap<String, Option<Record>>,
        /// The validity judge. Never persisted; rebuilt from `records`.
        cache: LeaseCache,
    }

    impl LeaseStore {
        /// Open (and load) the store for this user, or return `None` if caching
        /// is disabled or the runtime directory cannot be used safely.
        ///
        /// Never fails: an unreadable, corrupt or wrong-version file loads as
        /// empty, and any refusal simply means "no caching", which is exactly
        /// the pre-cache behaviour.
        #[must_use]
        pub fn open(env: &impl EnvSource) -> Option<Self> {
            if env
                .get(crate::selector::env::NO_LEASE_CACHE)
                .is_some_and(|v| !v.is_empty())
            {
                tracing::debug!("lease cache disabled by environment");
                return None;
            }
            let dir = runtime_dir(env);
            Self::open_at(&dir)
        }

        /// Open a store rooted at an explicit directory. The seam the unit and
        /// integration tests drive; [`LeaseStore::open`] is this plus the
        /// environment policy.
        #[must_use]
        pub fn open_at(dir: &Path) -> Option<Self> {
            if let Err(error) = prepare_dir(dir) {
                tracing::debug!(%error, dir = %dir.display(), "lease cache unavailable");
                return None;
            }
            let path = dir.join(FILE_NAME);
            let records = read_records(&path);
            let mut store = Self {
                dir: dir.to_path_buf(),
                path,
                records: BTreeMap::new(),
                pending: BTreeMap::new(),
                cache: LeaseCache::new(),
            };
            store.adopt(records);
            Some(store)
        }

        /// Replace the loaded record set (and the cache built from it).
        ///
        /// The cache is keyed on `(selector fingerprint, SubjectKey)`, which is
        /// *coarser* than the file key: two records under one selector for one
        /// subject — two coordinators, or a stale entry from a previous login —
        /// would otherwise collide, and a lookup that found the right `Record`
        /// by digest would judge it against another record's expiry. So each
        /// entry is inserted under a **synthetic** `SubjectKey` whose id folds
        /// in the record's digest: distinct records stay distinct, and the org /
        /// kind that matter for the org-collision rules ride along unchanged.
        /// Nothing reads this key back out — the real holder lives in
        /// `Record::holder` — so the synthesis is invisible outside `adopt` and
        /// [`LeaseStore::get`].
        fn adopt(&mut self, records: Vec<Record>) {
            self.cache = LeaseCache::new();
            self.records = BTreeMap::new();
            for record in records {
                let Ok(select) = parse_selector_key(&record.selector) else {
                    continue;
                };
                let digest = record.key().digest();
                let mut cached = CachedLease::new(record.grant());
                cached.refresh_margin_secs = record.refresh_margin_secs;
                let Some(cache_key) = cache_key_for(&record.holder, &digest) else {
                    continue;
                };
                self.cache.insert(&select, &cache_key, cached);
                self.records.insert(digest, record);
            }
        }

        /// The fingerprint of a bearer token, as stored. Public so callers can
        /// key without re-deriving the hash shape.
        #[must_use]
        pub fn token_fingerprint(token: &str) -> String {
            let mut hasher = Sha256::new();
            hasher.update(token.as_bytes());
            hex16(&hasher.finalize())
        }

        /// Look up a still-valid lease for `(coordinator, token, select)`.
        ///
        /// Returns the record **and** the use-guard that makes taking the hit
        /// exclusive. `None` covers every reason not to hit — no entry, expired
        /// or inside its refresh margin, or another live invocation holding the
        /// slot — and every one of them means "lease normally".
        #[must_use]
        pub fn get(
            &mut self,
            coordinator: &str,
            token: &str,
            select: &Constraint,
            now_secs: u64,
        ) -> Option<(Record, UseGuard)> {
            let key = Self::key_for(coordinator, token, select);
            let digest = key.digest();
            let record = self.records.get(&digest)?.clone();
            // The validity judgement lives in `lease_cache`, not here — under
            // the same synthetic subject `adopt` inserted it with, so one
            // record's expiry can never be read for another's.
            self.cache
                .get(select, &cache_key_for(&record.holder, &digest)?, now_secs)?;
            let guard = self.lock_use(&digest)?;
            Some((record, guard))
        }

        /// Take the use-lock for `(coordinator, token, select)` without
        /// requiring an entry — the cold path's claim on the cache slot.
        #[must_use]
        pub fn claim(
            &self,
            coordinator: &str,
            token: &str,
            select: &Constraint,
        ) -> Option<UseGuard> {
            self.lock_use(&Self::key_for(coordinator, token, select).digest())
        }

        /// Record (or replace) the lease for `(coordinator, token, select)`.
        ///
        /// Only a [`SubjectKind::User`] holder is stored (Decision 2, Guard A);
        /// anything else returns `false` and must be released at exit.
        pub fn record(
            &mut self,
            coordinator: &str,
            token: &str,
            select: &Constraint,
            grant: &LeaseGrant,
        ) -> bool {
            if grant.holder.kind() != SubjectKind::User {
                tracing::debug!(
                    kind = %grant.holder.kind(),
                    "not caching a non-user lease; it is released at exit"
                );
                return false;
            }
            let key = Self::key_for(coordinator, token, select);
            let record = Record {
                coordinator: key.coordinator.clone(),
                token_fp: key.token_fp.clone(),
                selector: key.selector.clone(),
                board: grant.board.clone(),
                node: grant.node.clone(),
                lease: grant.lease,
                holder: grant.holder.clone(),
                expires: grant.expires,
                refresh_margin_secs: CachedLease::DEFAULT_REFRESH_MARGIN_SECS,
            };
            let digest = key.digest();
            self.records.insert(digest.clone(), record.clone());
            self.pending.insert(digest, Some(record));
            true
        }

        /// Update a stored entry's expiry (after a heartbeat or revalidation).
        pub fn touch_expiry(
            &mut self,
            coordinator: &str,
            token: &str,
            select: &Constraint,
            expires: u64,
        ) {
            let digest = Self::key_for(coordinator, token, select).digest();
            if let Some(record) = self.records.get_mut(&digest) {
                record.expires = expires;
                let updated = record.clone();
                self.pending.insert(digest, Some(updated));
            }
        }

        /// Forget a stored entry (it was refused, released, or names the wrong
        /// board).
        pub fn forget(&mut self, coordinator: &str, token: &str, select: &Constraint) {
            let digest = Self::key_for(coordinator, token, select).digest();
            self.records.remove(&digest);
            self.pending.insert(digest, None);
        }

        /// Flush pending mutations to disk under the file lock.
        ///
        /// Re-reads the file while holding `leases.lock` and merges our
        /// mutations into what it finds, so two racing invocations cannot clobber
        /// each other's *different* entries. Expired records are dropped on the
        /// way through. Best-effort: a failure means the next invocation misses,
        /// which is not worth an error.
        ///
        /// # Blocking I/O on the runtime
        ///
        /// This takes a *blocking* `LOCK_EX` and does the read/write/`fsync`
        /// inline, on whatever thread calls it — in practice a tokio worker.
        /// Deliberate, and safe in proportion: the critical section is a few
        /// hundred bytes of JSON between two invocations of the same user, so it
        /// runs in well under a millisecond, and it happens a handful of times
        /// per process (never inside the splice loop). The one way it could
        /// stall is a foreign holder stopped mid-`save` (`SIGSTOP`, a debugger),
        /// which would block this thread for as long as that lasts. Moving it to
        /// `spawn_blocking` would buy nothing against that — the invocation
        /// cannot proceed without the store either way — and would cost the
        /// `&mut self` borrow that keeps the merge honest.
        pub fn save(&mut self, now_secs: u64) {
            if self.pending.is_empty() {
                return;
            }
            let Some(_lock) = lock_file(&self.dir.join(FILE_LOCK_NAME), true) else {
                tracing::debug!("could not lock the lease store; not persisting");
                return;
            };
            let mut merged: BTreeMap<String, Record> = read_records(&self.path)
                .into_iter()
                .map(|r| (r.key().digest(), r))
                .collect();
            for (digest, change) in std::mem::take(&mut self.pending) {
                match change {
                    Some(record) => {
                        merged.insert(digest, record);
                    }
                    None => {
                        merged.remove(&digest);
                    }
                }
            }
            merged.retain(|_, record| record.expires > now_secs);
            let body = FileBody {
                version: FORMAT_VERSION,
                records: merged.values().cloned().collect(),
            };
            if let Err(error) = write_atomically(&self.path, &body) {
                tracing::debug!(%error, "could not persist the lease store");
                return;
            }
            let records = body.records;
            self.adopt(records);
        }

        /// The store's file, for diagnostics and tests.
        #[must_use]
        pub fn path(&self) -> &Path {
            &self.path
        }

        fn key_for(coordinator: &str, token: &str, select: &Constraint) -> RecordKey {
            RecordKey {
                coordinator: coordinator.to_owned(),
                token_fp: Self::token_fingerprint(token),
                selector: fingerprint(select),
            }
        }

        /// Take a record's use-lock, non-blocking. `None` = somebody else is
        /// live on this record, or the lock file is unusable.
        fn lock_use(&self, digest: &str) -> Option<UseGuard> {
            let path = self.dir.join(format!("use-{digest}.lock"));
            lock_file(&path, false).map(|file| UseGuard { _file: file })
        }
    }

    /// The [`SubjectKey`] a record is cached under: the real holder with the
    /// record's digest folded into the id, so records that share a selector and
    /// a subject but differ in coordinator or token never alias. See
    /// [`LeaseStore::adopt`].
    ///
    /// `None` only if the holder could not have been built through
    /// [`SubjectKey::new`] in the first place (a hand-edited file); such a
    /// record is simply not cached.
    fn cache_key_for(holder: &SubjectKey, digest: &str) -> Option<SubjectKey> {
        SubjectKey::new(
            holder.ns(),
            holder.kind(),
            &format!("{}#{digest}", holder.id()),
        )
    }

    /// Resolve the runtime directory: `$XDG_RUNTIME_DIR/probe-rs-fleet`, or a
    /// uid-scoped fallback under the system temp directory when it is unset
    /// (some CI images and bare `su` sessions have no runtime dir).
    fn runtime_dir(env: &impl EnvSource) -> PathBuf {
        if let Some(dir) = env.get("XDG_RUNTIME_DIR").filter(|d| !d.is_empty()) {
            return PathBuf::from(dir).join(DIR_NAME);
        }
        let uid = rustix::process::getuid().as_raw();
        std::env::temp_dir().join(format!("{DIR_NAME}-{uid}"))
    }

    /// Create the directory 0700 if needed, and refuse it if it is not ours.
    fn prepare_dir(dir: &Path) -> std::io::Result<()> {
        use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _};

        if !dir.exists() {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)?;
        }
        let meta = std::fs::metadata(dir)?;
        if !meta.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotADirectory,
                "lease store path is not a directory",
            ));
        }
        // A directory somebody else owns could be planted with entries naming
        // boards we do not hold. Refusing costs one extra lease.
        if meta.uid() != rustix::process::getuid().as_raw() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "lease store directory is owned by another user",
            ));
        }
        Ok(())
    }

    /// Read the records, treating every failure as an empty store.
    fn read_records(path: &Path) -> Vec<Record> {
        let Ok(bytes) = std::fs::read(path) else {
            return Vec::new();
        };
        match serde_json::from_slice::<FileBody>(&bytes) {
            Ok(body) if body.version == FORMAT_VERSION => body.records,
            Ok(body) => {
                tracing::debug!(
                    version = body.version,
                    "ignoring a lease store written by another version"
                );
                Vec::new()
            }
            Err(error) => {
                tracing::debug!(%error, "ignoring an unreadable lease store");
                Vec::new()
            }
        }
    }

    /// Write `body` to `path` via a 0600 temp file + `fsync` + `rename`, so a
    /// reader never sees a half-written file.
    fn write_atomically(path: &Path, body: &FileBody) -> std::io::Result<()> {
        use std::os::unix::fs::OpenOptionsExt as _;

        let bytes = serde_json::to_vec_pretty(body)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
        {
            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
        }
        match std::fs::rename(&tmp, path) {
            Ok(()) => Ok(()),
            Err(error) => {
                let _ = std::fs::remove_file(&tmp);
                Err(error)
            }
        }
    }

    /// `flock` `path`, creating it 0600. `blocking` picks `LOCK_EX` over
    /// `LOCK_EX | LOCK_NB`; the returned file must be kept alive for the lock's
    /// lifetime.
    fn lock_file(path: &Path, blocking: bool) -> Option<File> {
        use std::os::unix::fs::OpenOptionsExt as _;

        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(path)
            .ok()?;
        let op = if blocking {
            rustix::fs::FlockOperation::LockExclusive
        } else {
            rustix::fs::FlockOperation::NonBlockingLockExclusive
        };
        rustix::fs::flock(&file, op).ok()?;
        Some(file)
    }

    /// Parse a [`crate::lease_cache::fingerprint`] back into a [`Constraint`],
    /// so a loaded record can be judged by [`LeaseCache`] under its own key.
    fn parse_selector_key(selector: &str) -> Result<Constraint, ()> {
        use fleet_proto::ids::BoardName;

        let (kind, value) = selector.split_once(':').ok_or(())?;
        match kind {
            "id" => Ok(Constraint::Id(BoardName(value.to_owned()))),
            "model" => Ok(Constraint::Model(value.to_owned())),
            "chip" => Ok(Constraint::Chip(value.to_owned())),
            "tags" => Ok(Constraint::Tags(
                value.split(',').map(ToOwned::to_owned).collect(),
            )),
            _ => Err(()),
        }
    }

    /// First 16 hex characters of a digest.
    fn hex16(digest: &[u8]) -> String {
        use std::fmt::Write as _;

        let mut s = String::with_capacity(16);
        for b in digest.iter().take(8) {
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use fleet_proto::ids::{BoardName, OrgId};

        fn grant(expires: u64, kind: SubjectKind) -> LeaseGrant {
            LeaseGrant {
                lease: LeaseId(7),
                board: BoardRef::new(
                    OrgId("default".to_owned()),
                    NodeId("node-a".to_owned()),
                    "b1",
                ),
                node: NodeId("node-a".to_owned()),
                holder: SubjectKey::new(None, kind, "alice").unwrap(),
                expires,
                token: vec![0xde, 0xad, 0xbe, 0xef],
            }
        }

        fn select() -> Constraint {
            Constraint::Id(BoardName("b1".to_owned()))
        }

        #[test]
        fn a_recorded_lease_survives_a_reopen() {
            let dir = tempfile::tempdir().unwrap();
            let mut store = LeaseStore::open_at(dir.path()).unwrap();
            assert!(store.record("c:1", "tok", &select(), &grant(10_000, SubjectKind::User)));
            store.save(1_000);

            let mut reopened = LeaseStore::open_at(dir.path()).unwrap();
            let (record, _guard) = reopened
                .get("c:1", "tok", &select(), 1_000)
                .expect("the entry survives the process boundary");
            assert_eq!(record.lease, LeaseId(7));
            assert_eq!(record.board.name, "b1");
        }

        #[test]
        fn a_different_token_or_coordinator_never_shares_an_entry() {
            let dir = tempfile::tempdir().unwrap();
            let mut store = LeaseStore::open_at(dir.path()).unwrap();
            store.record("c:1", "tok", &select(), &grant(10_000, SubjectKind::User));
            store.save(1_000);

            assert!(store.get("c:1", "other-token", &select(), 1_000).is_none());
            assert!(store.get("c:2", "tok", &select(), 1_000).is_none());
            assert!(store
                .get(
                    "c:1",
                    "tok",
                    &Constraint::Model("nrf52840dk".to_owned()),
                    1_000
                )
                .is_none());
        }

        #[test]
        fn two_records_sharing_a_selector_and_subject_never_alias() {
            // The in-memory cache is keyed on (selector, SubjectKey), which is
            // coarser than the file key. Two coordinators (or a stale entry
            // from a previous login) with the same selector and the same user
            // would collide, and a lookup that found the right `Record` by
            // digest would judge it against the *other* record's expiry. The
            // digest folded into the cached subject is what keeps them apart.
            let dir = tempfile::tempdir().unwrap();
            let mut store = LeaseStore::open_at(dir.path()).unwrap();
            // Same selector, same holder, different coordinator; the second one
            // is long-lived, the first expires soon.
            store.record("c:1", "tok", &select(), &grant(2_000, SubjectKind::User));
            store.record("c:2", "tok", &select(), &grant(500_000, SubjectKind::User));
            store.save(1_000);

            let mut store = LeaseStore::open_at(dir.path()).unwrap();
            // Each is judged against its own expiry: at t=100_000 the first is
            // long gone and the second is still fine.
            assert!(
                store.get("c:1", "tok", &select(), 100_000).is_none(),
                "the short-lived entry must not inherit the other's expiry"
            );
            assert!(
                store.get("c:2", "tok", &select(), 100_000).is_some(),
                "the long-lived entry must not inherit the other's expiry"
            );
            // And at t=1_000 both are valid and distinct.
            let mut store = LeaseStore::open_at(dir.path()).unwrap();
            let (first, _g1) = store.get("c:1", "tok", &select(), 1_000).unwrap();
            assert_eq!(first.coordinator, "c:1");
            assert_eq!(first.expires, 2_000);
            let (second, _g2) = store.get("c:2", "tok", &select(), 1_000).unwrap();
            assert_eq!(second.coordinator, "c:2");
            assert_eq!(second.expires, 500_000);
        }

        #[test]
        fn an_expired_entry_is_never_handed_out_and_is_swept_on_save() {
            let dir = tempfile::tempdir().unwrap();
            let mut store = LeaseStore::open_at(dir.path()).unwrap();
            store.record("c:1", "tok", &select(), &grant(2_000, SubjectKind::User));
            store.save(1_000);

            // Past expiry: no hit.
            assert!(store.get("c:1", "tok", &select(), 3_000).is_none());
            // Inside the refresh margin: still no hit — `lease_cache`'s rule.
            let mut fresh = LeaseStore::open_at(dir.path()).unwrap();
            assert!(fresh.get("c:1", "tok", &select(), 1_990).is_none());

            // A save past expiry drops it from the file.
            fresh.record("c:1", "tok2", &select(), &grant(10_000, SubjectKind::User));
            fresh.save(3_000);
            let text = std::fs::read_to_string(fresh.path()).unwrap();
            assert_eq!(text.matches("\"lease\"").count(), 1, "only the live entry");
        }

        #[test]
        fn forget_removes_the_entry_from_the_file() {
            let dir = tempfile::tempdir().unwrap();
            let mut store = LeaseStore::open_at(dir.path()).unwrap();
            store.record("c:1", "tok", &select(), &grant(10_000, SubjectKind::User));
            store.save(1_000);
            store.forget("c:1", "tok", &select());
            store.save(1_000);

            let mut reopened = LeaseStore::open_at(dir.path()).unwrap();
            assert!(reopened.get("c:1", "tok", &select(), 1_000).is_none());
        }

        #[test]
        fn touch_expiry_extends_a_stored_entry() {
            let dir = tempfile::tempdir().unwrap();
            let mut store = LeaseStore::open_at(dir.path()).unwrap();
            store.record("c:1", "tok", &select(), &grant(2_000, SubjectKind::User));
            store.save(1_000);
            store.touch_expiry("c:1", "tok", &select(), 20_000);
            store.save(1_000);

            let mut reopened = LeaseStore::open_at(dir.path()).unwrap();
            let (record, _guard) = reopened.get("c:1", "tok", &select(), 5_000).unwrap();
            assert_eq!(record.expires, 20_000);
        }

        #[test]
        fn a_workload_lease_is_never_cached() {
            let dir = tempfile::tempdir().unwrap();
            let mut store = LeaseStore::open_at(dir.path()).unwrap();
            assert!(
                !store.record(
                    "c:1",
                    "tok",
                    &select(),
                    &grant(10_000, SubjectKind::Workload)
                ),
                "CI must not strand a board for a policy TTL"
            );
            assert!(
                !store.record("c:1", "tok", &select(), &grant(10_000, SubjectKind::Node)),
                "a node lease is not a developer's session either"
            );
            store.save(1_000);
            assert!(store.get("c:1", "tok", &select(), 1_000).is_none());
        }

        #[test]
        fn no_secret_material_reaches_the_disk() {
            let dir = tempfile::tempdir().unwrap();
            let mut store = LeaseStore::open_at(dir.path()).unwrap();
            store.record(
                "c:1",
                "super-secret-bearer",
                &select(),
                &grant(10_000, SubjectKind::User),
            );
            store.save(1_000);
            let text = std::fs::read_to_string(store.path()).unwrap();
            assert!(
                !text.contains("super-secret-bearer"),
                "the bearer token must never be written"
            );
            assert!(
                !text.contains("deadbeef") && !text.contains("222"),
                "the grant's capability token must never be written: {text}"
            );
        }

        #[test]
        fn the_file_and_directory_are_private() {
            use std::os::unix::fs::PermissionsExt as _;

            let dir = tempfile::tempdir().unwrap();
            let root = dir.path().join("runtime");
            let mut store = LeaseStore::open_at(&root).unwrap();
            store.record("c:1", "tok", &select(), &grant(10_000, SubjectKind::User));
            store.save(1_000);

            let dir_mode = std::fs::metadata(&root).unwrap().permissions().mode() & 0o777;
            assert_eq!(dir_mode, 0o700, "the runtime directory is ours alone");
            let file_mode = std::fs::metadata(store.path())
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(file_mode, 0o600, "the store is ours alone");
        }

        #[test]
        fn a_corrupt_or_future_file_loads_as_empty_rather_than_failing() {
            let dir = tempfile::tempdir().unwrap();
            std::fs::write(dir.path().join(FILE_NAME), b"{ this is not json").unwrap();
            let mut store = LeaseStore::open_at(dir.path()).expect("a corrupt file is not fatal");
            assert!(store.get("c:1", "tok", &select(), 1_000).is_none());

            std::fs::write(
                dir.path().join(FILE_NAME),
                br#"{"version":999,"records":[]}"#,
            )
            .unwrap();
            let mut store = LeaseStore::open_at(dir.path()).expect("a future version is not fatal");
            assert!(store.get("c:1", "tok", &select(), 1_000).is_none());
            // And it is simply overwritten.
            store.record("c:1", "tok", &select(), &grant(10_000, SubjectKind::User));
            store.save(1_000);
            let mut reopened = LeaseStore::open_at(dir.path()).unwrap();
            assert!(reopened.get("c:1", "tok", &select(), 1_000).is_some());
        }

        #[test]
        fn a_live_use_lock_blocks_a_second_hit() {
            let dir = tempfile::tempdir().unwrap();
            let mut store = LeaseStore::open_at(dir.path()).unwrap();
            store.record("c:1", "tok", &select(), &grant(10_000, SubjectKind::User));
            store.save(1_000);

            let mut first = LeaseStore::open_at(dir.path()).unwrap();
            let (_record, guard) = first.get("c:1", "tok", &select(), 1_000).unwrap();

            let mut second = LeaseStore::open_at(dir.path()).unwrap();
            assert!(
                second.get("c:1", "tok", &select(), 1_000).is_none(),
                "a second live invocation must fall through to a fresh Lease"
            );

            // Releasing the slot lets the next invocation hit again — this is
            // also what the kernel does for us when a holder is SIGKILLed.
            //
            // Retried rather than asserted once: an `flock` lives on the *open
            // file description*, so any `fork()` elsewhere in this process
            // duplicates the fd and keeps the lock pinned until that child
            // `exec`s (`O_CLOEXEC` only fires at exec, not at fork). With the
            // rest of the suite spawning processes in parallel, a re-acquire
            // immediately after a drop can transiently lose that race — which
            // is a property of the test harness, not of the store: in the real
            // sidecar the next invocation is a whole new process, arriving
            // milliseconds later. See the `fork()` caveat in the module doc.
            drop(guard);
            let mut hit = None;
            for _ in 0..200 {
                hit = second.get("c:1", "tok", &select(), 1_000);
                if hit.is_some() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            assert!(
                hit.is_some(),
                "the slot must become reusable once the holder lets go"
            );
        }

        #[test]
        fn a_use_lock_on_one_record_does_not_block_another() {
            let dir = tempfile::tempdir().unwrap();
            let store = LeaseStore::open_at(dir.path()).unwrap();
            let _a = store.claim("c:1", "tok", &select()).unwrap();
            assert!(
                store
                    .claim("c:1", "tok", &Constraint::Model("other".to_owned()))
                    .is_some(),
                "records are locked independently"
            );
        }

        #[test]
        fn concurrent_saves_lose_no_entries() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().to_path_buf();
            let threads: Vec<_> = (0..8)
                .map(|i| {
                    let path = path.clone();
                    std::thread::spawn(move || {
                        for j in 0..25 {
                            let mut store = LeaseStore::open_at(&path).unwrap();
                            let token = format!("tok-{i}-{j}");
                            store.record(
                                "c:1",
                                &token,
                                &select(),
                                &grant(1_000_000, SubjectKind::User),
                            );
                            store.save(1_000);
                        }
                    })
                })
                .collect();
            for t in threads {
                t.join().unwrap();
            }

            let mut store = LeaseStore::open_at(&path).unwrap();
            for i in 0..8 {
                for j in 0..25 {
                    let token = format!("tok-{i}-{j}");
                    assert!(
                        store.get("c:1", &token, &select(), 1_000).is_some(),
                        "entry {token} was lost to a racing writer"
                    );
                }
            }
        }

        #[test]
        fn a_selector_fingerprint_round_trips_for_every_constraint_shape() {
            for select in [
                Constraint::Id(BoardName("b1".to_owned())),
                Constraint::Model("nrf52840dk".to_owned()),
                Constraint::Chip("nRF52840_xxAA".to_owned()),
                Constraint::Tags(vec!["ci".to_owned(), "usb".to_owned()]),
            ] {
                let key = fingerprint(&select);
                let parsed = parse_selector_key(&key).expect("a key we wrote parses back");
                assert_eq!(fingerprint(&parsed), key);
            }
        }

        #[test]
        fn the_environment_opt_out_disables_caching() {
            struct Env(Vec<(String, String)>);
            impl EnvSource for Env {
                fn get(&self, key: &str) -> Option<String> {
                    self.0
                        .iter()
                        .find(|(k, _)| k == key)
                        .map(|(_, v)| v.clone())
                }
            }

            let dir = tempfile::tempdir().unwrap();
            let env = Env(vec![
                (
                    "XDG_RUNTIME_DIR".to_owned(),
                    dir.path().to_string_lossy().into_owned(),
                ),
                (
                    crate::selector::env::NO_LEASE_CACHE.to_owned(),
                    "1".to_owned(),
                ),
            ]);
            assert!(LeaseStore::open(&env).is_none());

            let env = Env(vec![(
                "XDG_RUNTIME_DIR".to_owned(),
                dir.path().to_string_lossy().into_owned(),
            )]);
            let store = LeaseStore::open(&env).expect("caching is on by default");
            assert!(store.path().starts_with(dir.path().join(DIR_NAME)));
        }

        #[test]
        fn a_directory_owned_by_another_user_disables_caching() {
            // /proc is root-owned on every Linux box and never ours in a test
            // run; there is no portable way to fabricate a foreign-owned
            // directory without privileges.
            if rustix::process::getuid().as_raw() == 0 {
                return;
            }
            let foreign = Path::new("/proc");
            if !foreign.is_dir() {
                return;
            }
            assert!(
                LeaseStore::open_at(foreign).is_none(),
                "a directory somebody else owns must not be trusted with leases"
            );
        }
    }
}

/// Non-unix stub: `$XDG_RUNTIME_DIR` and `flock` are unix concepts, so caching
/// is simply off and the sidecar behaves exactly as it did before the store
/// existed (lease and release per invocation).
#[cfg(not(unix))]
mod other_imp {
    use fleet_proto::ids::{BoardRef, NodeId, SubjectKey};
    use fleet_proto::lease::{Constraint, LeaseGrant};
    use fleet_proto::LeaseId;

    use crate::selector::EnvSource;

    /// A persisted lease. Unreachable off unix — the store never yields one.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Record {
        /// Coordinator base URL.
        pub coordinator: String,
        /// The bearer token's fingerprint.
        pub token_fp: String,
        /// The selector fingerprint.
        pub selector: String,
        /// The leased board.
        pub board: BoardRef,
        /// The node hosting it.
        pub node: NodeId,
        /// The lease.
        pub lease: LeaseId,
        /// The holder.
        pub holder: SubjectKey,
        /// Expiry, epoch seconds.
        pub expires: u64,
        /// Refresh margin.
        pub refresh_margin_secs: u64,
    }

    impl Record {
        /// Rebuild a [`LeaseGrant`] from this record, with an empty token.
        ///
        /// Off unix the store never yields a `Record`, so nothing in the crate
        /// calls this — but `Record`'s fields are public, so a caller could
        /// build one anyway. It returns the same empty-token grant the unix
        /// implementation does rather than panicking: an unreachable branch is
        /// not worth a crash in somebody else's code.
        #[must_use]
        pub fn grant(&self) -> LeaseGrant {
            LeaseGrant {
                lease: self.lease,
                board: self.board.clone(),
                node: self.node.clone(),
                holder: self.holder.clone(),
                expires: self.expires,
                token: Vec::new(),
            }
        }
    }

    /// What `hold_and_run` should do with the lease on the way out.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Disposition {
        /// Release at exit. The only disposition off unix.
        Release,
        /// Keep for the next invocation.
        Keep,
    }

    /// An RAII holder for a record's use-lock. Never constructed off unix.
    #[derive(Debug)]
    pub struct UseGuard {
        _private: (),
    }

    /// The lease store. Off unix every constructor yields `None`.
    #[derive(Debug)]
    pub struct LeaseStore {
        _private: (),
    }

    impl LeaseStore {
        /// Always `None`: no runtime directory, no advisory locks, no caching.
        #[must_use]
        pub fn open(_env: &impl EnvSource) -> Option<Self> {
            None
        }

        /// Always `None`, as [`LeaseStore::open`].
        #[must_use]
        pub fn open_at(_dir: &std::path::Path) -> Option<Self> {
            None
        }

        /// The fingerprint of a bearer token. Present so callers stay cfg-free.
        #[must_use]
        pub fn token_fingerprint(token: &str) -> String {
            use sha2::{Digest as _, Sha256};
            use std::fmt::Write as _;

            let mut hasher = Sha256::new();
            hasher.update(token.as_bytes());
            let digest = hasher.finalize();
            let mut s = String::with_capacity(16);
            for b in digest.iter().take(8) {
                let _ = write!(s, "{b:02x}");
            }
            s
        }

        /// Never a hit.
        #[must_use]
        pub fn get(
            &mut self,
            _coordinator: &str,
            _token: &str,
            _select: &Constraint,
            _now_secs: u64,
        ) -> Option<(Record, UseGuard)> {
            None
        }

        /// Never claims a slot.
        #[must_use]
        pub fn claim(
            &self,
            _coordinator: &str,
            _token: &str,
            _select: &Constraint,
        ) -> Option<UseGuard> {
            None
        }

        /// Never records.
        pub fn record(
            &mut self,
            _coordinator: &str,
            _token: &str,
            _select: &Constraint,
            _grant: &LeaseGrant,
        ) -> bool {
            false
        }

        /// No-op.
        pub fn touch_expiry(
            &mut self,
            _coordinator: &str,
            _token: &str,
            _select: &Constraint,
            _expires: u64,
        ) {
        }

        /// No-op.
        pub fn forget(&mut self, _coordinator: &str, _token: &str, _select: &Constraint) {}

        /// No-op.
        pub fn save(&mut self, _now_secs: u64) {}
    }
}

// Two `mod`s, one API. The re-export is what keeps every call site cfg-free;
// the modules are named apart rather than both called `imp` so that tooling
// which reads the file without evaluating `cfg` (the merge queue's structural
// check, for one) does not see two definitions of every symbol.
#[cfg(not(unix))]
pub use other_imp::{Disposition, LeaseStore, Record, UseGuard};
#[cfg(unix)]
pub use unix_imp::{Disposition, LeaseStore, Record, UseGuard};
