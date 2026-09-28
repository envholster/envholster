//! envholster-mem — locked secret memory (frozen API: plan/04-contracts §4.2).
//!
//! Semantics, rationale, and gates: plan/03-memory. Backend: `memsec` =0.7.0
//! (guarded allocation, `mlock`, `mprotect(PROT_NONE)` outside borrows,
//! zero-on-free).
//!
//! This is the ONLY workspace crate WITHOUT `#![forbid(unsafe_code)]` — every
//! first-party `unsafe` line lives here: allocation, process hardening, and
//! Unix signal/terminal control. Dependencies have their own unsafe code.
//! A CI grep gate enforces the attribute on every other workspace crate.
//! Every unsafe block carries a `SAFETY:` comment stating its invariant.
//!
//! Fail-closed (c23): every constructor is fallible; a failed lock is a typed
//! error, never a silent downgrade to swappable memory. memsec's `_malloc`
//! *swallows* its internal `mlock` return code, so this crate re-probes the
//! freshly allocated region with raw `libc::mlock` and frees + surfaces a
//! typed error on a nonzero rc — the allocator's own success claim is never
//! trusted (c23). Exposure only via closures; `Debug` prints
//! `SecretBytes(<redacted>)`; drop zeroizes; arena-issued `SecretBytes` share
//! the arena's locked pages.

#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(not(unix))]
compile_error!(
    "envholster-mem supports Unix (macOS/Linux) only: the fail-closed lock \
     probes use raw libc::mlock / getrlimit"
);

pub mod process;

use core::cell::Cell;
use core::ptr::NonNull;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use zeroize::Zeroize;

/// memsec =0.7.0 places a 16-byte canary immediately before the user pointer,
/// inside the same locked, guarded region. Pinned internal layout fact of the
/// exact `=0.7.0` dependency (hand-reviewed; D12 `=` pin): used only to keep
/// the raw-`mlock` probe range inside the unprotected region and to account
/// the region's locked span (`page_round(CANARY + len)` mirrors `_malloc`).
const MEMSEC_CANARY_SIZE: usize = 16;

/// Bytes this process has locked through this crate (memsec regions we
/// created). Advisory accounting for `lock_budget()` / `LockExhausted`
/// messages; the raw `libc::mlock` rc stays the ground truth per allocation.
static LOCKED_BYTES: AtomicU64 = AtomicU64::new(0);

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Typed failure of the locked allocator (plan/03-memory §3.2, c23).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MemError {
    /// Guarded alloc returned NULL (or entropy could not be sourced into a
    /// locked buffer — the buffer is zeroized and freed before surfacing).
    #[error("guarded secure allocation failed (allocator returned NULL)")]
    AllocFailed,
    /// RLIMIT_MEMLOCK budget exhausted (or a `SecretArena` pool is full —
    /// the arena exists precisely to make that budget hold, plan/03 §3.5).
    #[error(
        "memory-lock budget exhausted: {locked_bytes} bytes locked of a {limit_bytes}-byte RLIMIT_MEMLOCK limit"
    )]
    LockExhausted {
        locked_bytes: usize,
        limit_bytes: usize,
    },
    /// Platform cannot lock memory at all.
    #[error("memory locking is unsupported on this platform")]
    LockUnsupported,
}

// ---------------------------------------------------------------------------
// Page / budget helpers
// ---------------------------------------------------------------------------

fn page_size() -> usize {
    static PAGE: OnceLock<usize> = OnceLock::new();
    *PAGE.get_or_init(|| {
        // SAFETY: sysconf(_SC_PAGESIZE) has no preconditions and touches no
        // caller memory.
        let ps = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if ps <= 0 {
            4096
        } else {
            ps as usize
        }
    })
}

/// Bytes memsec locks for a user allocation of `len`: the page-rounded
/// canary+data span (mirrors `_malloc`'s `unprotected_size`). Guard pages are
/// PROT_NONE but never mlocked, so they do not count against RLIMIT_MEMLOCK.
fn locked_span(len: usize) -> usize {
    let p = page_size();
    (MEMSEC_CANARY_SIZE + len).div_ceil(p) * p
}

/// `Ok(None)` = no limit (RLIM_INFINITY); `Err` = getrlimit itself failed.
fn memlock_limit() -> Result<Option<u64>, MemError> {
    let mut rl = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes into the valid, owned `rl` out-parameter.
    let rc = unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut rl) };
    if rc != 0 {
        return Err(MemError::LockUnsupported);
    }
    if rl.rlim_cur == libc::RLIM_INFINITY {
        Ok(None)
    } else {
        // `rlim_t` is `u64` on both supported targets (macOS and Linux glibc/musl),
        // so no widening cast is needed here.
        Ok(Some(rl.rlim_cur))
    }
}

fn lock_exhausted_now() -> MemError {
    MemError::LockExhausted {
        locked_bytes: LOCKED_BYTES.load(Ordering::SeqCst) as usize,
        limit_bytes: memlock_limit()
            .ok()
            .flatten()
            .map(|l| l as usize)
            .unwrap_or(usize::MAX),
    }
}

/// Advisory pre-flight against RLIMIT_MEMLOCK so an over-budget request fails
/// with the typed error before allocating. The post-alloc raw-mlock probe
/// stays authoritative (other libraries' locked pages are invisible here).
fn precheck_budget(len: usize) -> Result<(), MemError> {
    if let Ok(Some(limit)) = memlock_limit() {
        let cur = LOCKED_BYTES.load(Ordering::SeqCst);
        if cur.saturating_add(locked_span(len) as u64) > limit {
            return Err(MemError::LockExhausted {
                locked_bytes: cur as usize,
                limit_bytes: limit as usize,
            });
        }
    }
    Ok(())
}

/// Fail-closed lock verification (c23): memsec's `_malloc` ignores its
/// internal `mlock` rc, so re-lock the region with raw `libc::mlock` and
/// surface a nonzero rc as a typed error. `mlock` on already-locked pages is
/// an idempotent success; if memsec's attempt silently failed, this one fails
/// observably. The probed range `[canary_page_start, round_up(user+len))` is
/// entirely inside the unprotected (RW at this point) region — it never
/// touches the PROT_NONE guard pages.
fn probe_lock(user: NonNull<u8>, len: usize) -> Result<(), MemError> {
    let page = page_size();
    let mask = page - 1;
    let addr = user.as_ptr() as usize;
    let start = (addr - MEMSEC_CANARY_SIZE) & !mask;
    let end = (addr + len + mask) & !mask;
    debug_assert!(end > start);
    // SAFETY: the range lies within the live memsec unprotected region
    // computed above; mlock reads no memory and has no aliasing requirements.
    let rc = unsafe { libc::mlock(start as *const libc::c_void, end - start) };
    if rc == 0 {
        return Ok(());
    }
    match std::io::Error::last_os_error().raw_os_error() {
        Some(libc::ENOMEM) | Some(libc::EAGAIN) => Err(lock_exhausted_now()),
        Some(libc::EPERM) | Some(libc::ENOSYS) => Err(MemError::LockUnsupported),
        _ => Err(MemError::AllocFailed),
    }
}

/// Allocate a guarded, verified-locked, RW memsec region of `len` user bytes.
/// Contents are memsec's 0xd0 garbage; the caller must overwrite then seal.
fn alloc_locked(len: usize) -> Result<NonNull<u8>, MemError> {
    precheck_budget(len)?;
    // SAFETY: malloc_sized has no caller preconditions; on Some it returns a
    // guarded, garbage-filled, ReadWrite region of exactly `len` user bytes.
    let raw: NonNull<[u8]> = unsafe { memsec::malloc_sized(len) }.ok_or(MemError::AllocFailed)?;
    let ptr = raw.cast::<u8>();
    if let Err(e) = probe_lock(ptr, len) {
        // Fail closed: never hand out an unlockable buffer. free() zeroizes.
        // SAFETY: ptr came from memsec::malloc_sized above and is unfreed.
        unsafe { memsec::free(ptr) };
        return Err(e);
    }
    LOCKED_BYTES.fetch_add(locked_span(len) as u64, Ordering::SeqCst);
    Ok(ptr)
}

/// mprotect the whole unprotected region of a memsec allocation.
/// Panics if the transition to a *readable* state fails (nothing was exposed
/// yet, so unwinding is safe and Drop still zeroizes+frees).
fn protect(ptr: NonNull<u8>, prot: memsec::Prot::Ty) {
    // SAFETY: ptr is a live memsec user pointer; memsec::mprotect derives the
    // region bounds from its (ReadOnly) base page.
    let ok = unsafe { memsec::mprotect(ptr, prot) };
    assert!(ok, "envholster-mem: mprotect transition failed");
}

/// Like `protect`, but for the return to PROT_NONE after an exposure. If
/// re-protection fails the plaintext would stay readable for the process
/// lifetime — fail closed by aborting (mirrors libsodium's canary abort).
fn protect_none_or_abort(ptr: NonNull<u8>) {
    // SAFETY: ptr is a live memsec user pointer (see `protect`).
    let ok = unsafe { memsec::mprotect(ptr, memsec::Prot::NoAccess) };
    if !ok {
        std::process::abort();
    }
}

/// Drop guard: returns a region to PROT_NONE even if the closure panics.
struct ProtectGuard(NonNull<u8>);
impl Drop for ProtectGuard {
    fn drop(&mut self) {
        protect_none_or_abort(self.0);
    }
}

/// Zero-on-free for a possibly-PROT_NONE memsec region. memsec's `free()`
/// canary-checks the region *before* its own mprotect(ReadWrite), so freeing
/// a sealed region would fault: make it readable first. `free()` then
/// re-protects, canary-checks, munlocks (which memzeroes the whole
/// unprotected region), and deallocates.
fn free_sealed(ptr: NonNull<u8>) {
    protect(ptr, memsec::Prot::ReadWrite);
    // SAFETY: ptr is a live memsec user pointer, freed exactly once here,
    // and the region was just made readable for free()'s canary check.
    unsafe { memsec::free(ptr) };
}

// ---------------------------------------------------------------------------
// Owned (dedicated-region) secrets
// ---------------------------------------------------------------------------

struct OwnedSecret {
    /// memsec user pointer; region protection is NoAccess whenever
    /// `read_depth == 0` and no `with_exposed_mut` frame is live.
    ptr: NonNull<u8>,
    /// Allocated user capacity (never changes; `truncate` only shrinks `len`).
    cap: usize,
    /// Logical length ≤ cap.
    len: usize,
    /// Nested `with_exposed` depth, so an inner read exposure does not
    /// re-protect the region out from under an outer one. `Cell` also keeps
    /// the type `!Sync`, which is what makes the unsynchronized protection
    /// flips in `with_exposed(&self)` sound.
    read_depth: Cell<usize>,
}

impl OwnedSecret {
    /// Region is left ReadWrite for the constructor to fill; call `seal`.
    fn alloc(len: usize) -> Result<Self, MemError> {
        let ptr = alloc_locked(len)?;
        Ok(OwnedSecret {
            ptr,
            cap: len,
            len,
            read_depth: Cell::new(0),
        })
    }

    fn seal(&self) {
        protect(self.ptr, memsec::Prot::NoAccess);
    }
}

impl Drop for OwnedSecret {
    fn drop(&mut self) {
        free_sealed(self.ptr);
        LOCKED_BYTES.fetch_sub(locked_span(self.cap) as u64, Ordering::SeqCst);
    }
}

/// Restores an owned secret's read exposure depth (and PROT_NONE at depth 0)
/// even if the user closure panics.
struct ReadGuard<'a>(&'a OwnedSecret);
impl Drop for ReadGuard<'_> {
    fn drop(&mut self) {
        let depth = self.0.read_depth.get() - 1;
        self.0.read_depth.set(depth);
        if depth == 0 {
            protect_none_or_abort(self.0.ptr);
        }
    }
}

// ---------------------------------------------------------------------------
// Arena internals
// ---------------------------------------------------------------------------

struct ArenaState {
    /// Bump offset of the next free byte. Reset to 0 when `live` returns to 0
    /// (every released range was already zeroized at its drop).
    offset: usize,
    /// Live arena-issued `SecretBytes`.
    live: usize,
    /// Active exposure count across all arena-issued secrets; the region is
    /// ReadWrite while > 0 and PROT_NONE at 0. Page protection has page
    /// granularity, so pooled secrets necessarily share an exposure window —
    /// the documented trade-off of pooling (plan/03 §3.2).
    exposures: usize,
}

struct ArenaInner {
    /// memsec user pointer of the shared pool region.
    ptr: NonNull<u8>,
    cap: usize,
    state: Mutex<ArenaState>,
}

// SAFETY: all protection flips and bump-state mutation go through the Mutex;
// issued byte ranges are pairwise disjoint by construction (bump allocation;
// ranges are reused only after every live secret has been dropped and
// zeroized), so cross-thread access never aliases. The raw pointer is only
// dereferenced inside exposure windows.
unsafe impl Send for ArenaInner {}
// SAFETY: see the Send justification above — &ArenaInner only reaches the
// region through mutex-serialized, exposure-counted protocol methods.
unsafe impl Sync for ArenaInner {}

impl ArenaInner {
    fn lock(&self) -> MutexGuard<'_, ArenaState> {
        // A poisoned lock only means a panic mid-update; the state stays
        // structurally valid (plain counters), so keep failing closed rather
        // than cascading panics.
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Reserve `len` bytes; returns the range's start offset.
    fn reserve(&self, len: usize) -> Result<usize, MemError> {
        let mut st = self.lock();
        if len > self.cap || st.offset > self.cap - len {
            // Arena exhaustion IS a lock-budget failure: the pool is sized
            // against RLIMIT_MEMLOCK (plan/03 §3.5).
            return Err(MemError::LockExhausted {
                locked_bytes: st.offset,
                limit_bytes: self.cap,
            });
        }
        let offset = st.offset;
        st.offset += len;
        st.live += 1;
        Ok(offset)
    }

    fn begin_exposure(&self) {
        let mut st = self.lock();
        if st.exposures == 0 {
            protect(self.ptr, memsec::Prot::ReadWrite);
        }
        st.exposures += 1;
    }

    fn end_exposure(&self) {
        let mut st = self.lock();
        st.exposures -= 1;
        if st.exposures == 0 {
            // SAFETY: ptr is a live memsec user pointer.
            let ok = unsafe { memsec::mprotect(self.ptr, memsec::Prot::NoAccess) };
            if !ok {
                // Plaintext would stay readable forever: fail closed.
                std::process::abort();
            }
        }
    }

    /// Zeroize `[offset, offset+len)` inside an exposure window.
    fn zeroize_range(&self, offset: usize, len: usize) {
        self.begin_exposure();
        let _guard = ArenaExposureGuard(self);
        // SAFETY: region is ReadWrite (exposure); the range is within cap and
        // belongs to exactly one live secret, so no Rust reference aliases it.
        unsafe { memsec::memzero(self.ptr.as_ptr().add(offset), len) };
    }

    /// Called from an arena-issued secret's Drop: zeroize, retire, and reset
    /// the bump offset once nothing is live.
    fn release(&self, offset: usize, len: usize) {
        self.zeroize_range(offset, len);
        let mut st = self.lock();
        st.live -= 1;
        if st.live == 0 {
            st.offset = 0;
        }
    }
}

impl Drop for ArenaInner {
    fn drop(&mut self) {
        // Zero-on-free of the whole pool via free_sealed (last Arc holder;
        // no live secrets or exposures can exist here).
        free_sealed(self.ptr);
        LOCKED_BYTES.fetch_sub(locked_span(self.cap) as u64, Ordering::SeqCst);
    }
}

/// Ends an arena exposure even if the closure panics.
struct ArenaExposureGuard<'a>(&'a ArenaInner);
impl Drop for ArenaExposureGuard<'_> {
    fn drop(&mut self) {
        self.0.end_exposure();
    }
}

struct ArenaRef {
    inner: Arc<ArenaInner>,
    offset: usize,
    len: usize,
}

// ---------------------------------------------------------------------------
// SecretBytes
// ---------------------------------------------------------------------------

enum Repr {
    Owned(OwnedSecret),
    Arena(ArenaRef),
}

/// The only type permitted to hold secret plaintext at rest in process memory
/// (plan/03-memory §3.2). Pages are `PROT_NONE` outside `with_exposed*`
/// closures; no `expose() -> &[u8]` may ever be added, and no `Clone` impl
/// may ever be added.
pub struct SecretBytes {
    repr: Repr,
}

// SAFETY: Owned secrets exclusively own their memsec region (protection flips
// happen through `&self`/`&mut self` on a single thread at a time — the type
// is deliberately `!Sync`, so `&SecretBytes` never crosses threads). Arena
// secrets hold an `Arc<ArenaInner>` whose region access is mutex-serialized
// and exposure-counted, and whose issued ranges are disjoint.
unsafe impl Send for SecretBytes {}

impl SecretBytes {
    /// Copies `src` into a fresh locked buffer. The caller remains
    /// responsible for zeroizing its own copy of `src`.
    pub fn try_from_slice(src: &[u8]) -> Result<Self, MemError> {
        let owned = OwnedSecret::alloc(src.len())?;
        // SAFETY: the fresh region is ReadWrite and valid for cap == src.len()
        // bytes; src cannot overlap a just-created allocation.
        unsafe { core::ptr::copy_nonoverlapping(src.as_ptr(), owned.ptr.as_ptr(), src.len()) };
        owned.seal();
        Ok(SecretBytes {
            repr: Repr::Owned(owned),
        })
    }

    /// Copies a `String`'s bytes into a locked buffer, then zeroizes and
    /// clears the source in place (its full capacity, via `zeroize`) whether
    /// or not the locked allocation succeeded. Additive convenience over the
    /// frozen §4.2 surface for the stdin/prompt paths, where the transient
    /// `String` must not linger in swappable heap.
    pub fn try_from_string(src: &mut String) -> Result<Self, MemError> {
        let out = Self::try_from_slice(src.as_bytes());
        src.zeroize();
        out
    }

    /// `getrandom::fill` directly into a locked buffer; DEK len = 32 (c19).
    pub fn try_random(len: usize) -> Result<Self, MemError> {
        let owned = OwnedSecret::alloc(len)?;
        // SAFETY: region is ReadWrite and valid for `len` bytes; no other
        // reference to it exists yet.
        let buf = unsafe { core::slice::from_raw_parts_mut(owned.ptr.as_ptr(), len) };
        if getrandom::fill(buf).is_err() {
            // Entropy failure maps onto AllocFailed (the frozen MemError set
            // has no entropy variant); dropping `owned` zeroizes + frees.
            return Err(MemError::AllocFailed);
        }
        owned.seal();
        Ok(SecretBytes {
            repr: Repr::Owned(owned),
        })
    }

    /// Zero-filled, pre-sized locked buffer (stdin input, in-place AEAD).
    pub fn try_with_capacity(len: usize) -> Result<Self, MemError> {
        let owned = OwnedSecret::alloc(len)?;
        // SAFETY: region is ReadWrite and valid for `len` bytes (memsec fills
        // with 0xd0 garbage; overwrite with zeros before sealing).
        unsafe { memsec::memzero(owned.ptr.as_ptr(), len) };
        owned.seal();
        Ok(SecretBytes {
            repr: Repr::Owned(owned),
        })
    }

    /// Read-only exposure for the closure's duration only. Nested read
    /// exposures of the same secret are permitted (depth-counted).
    pub fn with_exposed<R>(&self, f: impl FnOnce(&[u8]) -> R) -> R {
        match &self.repr {
            Repr::Owned(o) => {
                if o.read_depth.get() == 0 {
                    protect(o.ptr, memsec::Prot::ReadOnly);
                }
                o.read_depth.set(o.read_depth.get() + 1);
                let _guard = ReadGuard(o);
                // SAFETY: region is ReadOnly for the guard's lifetime; no
                // `&mut` can exist (with_exposed_mut needs `&mut self`);
                // len ≤ cap.
                let slice = unsafe { core::slice::from_raw_parts(o.ptr.as_ptr(), o.len) };
                f(slice)
            }
            Repr::Arena(a) => {
                a.inner.begin_exposure();
                let _guard = ArenaExposureGuard(&a.inner);
                // SAFETY: region is readable (exposure); this secret's range
                // is disjoint from every other live range, and no `&mut` to
                // it exists (would need `&mut self`).
                let slice = unsafe {
                    core::slice::from_raw_parts(a.inner.ptr.as_ptr().add(a.offset), a.len)
                };
                f(slice)
            }
        }
    }

    /// Mutable exposure — in-place AEAD + HB1 encode/parse happen here (c6).
    pub fn with_exposed_mut<R>(&mut self, f: impl FnOnce(&mut [u8]) -> R) -> R {
        match &mut self.repr {
            Repr::Owned(o) => {
                debug_assert_eq!(o.read_depth.get(), 0);
                protect(o.ptr, memsec::Prot::ReadWrite);
                let _guard = ProtectGuard(o.ptr);
                // SAFETY: region is ReadWrite for the guard's lifetime; the
                // `&mut self` receiver guarantees exclusivity; len ≤ cap.
                let slice = unsafe { core::slice::from_raw_parts_mut(o.ptr.as_ptr(), o.len) };
                f(slice)
            }
            Repr::Arena(a) => {
                a.inner.begin_exposure();
                let _guard = ArenaExposureGuard(&a.inner);
                // SAFETY: region is ReadWrite (exposure); this secret's range
                // is disjoint from every other live range, and `&mut self`
                // guarantees no other reference into this range exists.
                let slice = unsafe {
                    core::slice::from_raw_parts_mut(a.inner.ptr.as_ptr().add(a.offset), a.len)
                };
                f(slice)
            }
        }
    }

    /// Post-decrypt shrink; never reallocates. The truncated tail is
    /// zeroized immediately (it may hold plaintext). `len >= self.len()` is a
    /// no-op.
    pub fn truncate(&mut self, len: usize) {
        match &mut self.repr {
            Repr::Owned(o) => {
                if len >= o.len {
                    return;
                }
                protect(o.ptr, memsec::Prot::ReadWrite);
                let _guard = ProtectGuard(o.ptr);
                // SAFETY: region is ReadWrite; `[len, o.len)` is within cap
                // and exclusively ours (`&mut self`).
                unsafe { memsec::memzero(o.ptr.as_ptr().add(len), o.len - len) };
                o.len = len;
            }
            Repr::Arena(a) => {
                if len >= a.len {
                    return;
                }
                a.inner.zeroize_range(a.offset + len, a.len - len);
                a.len = len;
            }
        }
    }

    pub fn len(&self) -> usize {
        match &self.repr {
            Repr::Owned(o) => o.len,
            Repr::Arena(a) => a.len,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Test-only: snapshot the full allocated capacity (owned) or range
    /// (arena) so tests can observe tail zeroization. Never compiled into
    /// non-test builds.
    #[cfg(test)]
    fn test_snapshot_capacity(&self) -> Vec<u8> {
        match &self.repr {
            Repr::Owned(o) => {
                if o.read_depth.get() == 0 {
                    protect(o.ptr, memsec::Prot::ReadOnly);
                }
                o.read_depth.set(o.read_depth.get() + 1);
                let _guard = ReadGuard(o);
                // SAFETY: region readable; cap is the allocated user size.
                unsafe { core::slice::from_raw_parts(o.ptr.as_ptr(), o.cap) }.to_vec()
            }
            Repr::Arena(a) => {
                a.inner.begin_exposure();
                let _guard = ArenaExposureGuard(&a.inner);
                // SAFETY: region readable; range within cap.
                unsafe { core::slice::from_raw_parts(a.inner.ptr.as_ptr().add(a.offset), a.len) }
                    .to_vec()
            }
        }
    }
}

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretBytes(<redacted>)")
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        // Owned: OwnedSecret::drop zeroizes + frees the dedicated region.
        // Arena: zeroize our range and retire it from the shared pool.
        if let Repr::Arena(a) = &self.repr {
            a.inner.release(a.offset, a.len);
        }
    }
}

// ---------------------------------------------------------------------------
// SecretArena
// ---------------------------------------------------------------------------

/// Shared locked pages for small secrets — a correctness requirement, not an
/// optimization: guarded allocation costs ≥3 pages (guard–data–guard), so at
/// Apple Silicon's 16 KiB pages naive per-secret allocations exhaust a 64 KiB
/// RLIMIT_MEMLOCK at n=1–2; the arena is why the budget holds
/// (plan/03-memory §3.2, §3.5).
pub struct SecretArena {
    inner: Arc<ArenaInner>,
}

impl SecretArena {
    pub fn try_with_capacity(bytes: usize) -> Result<Self, MemError> {
        let ptr = alloc_locked(bytes)?;
        // SAFETY: fresh region is ReadWrite and valid for `bytes` bytes;
        // overwrite memsec's garbage fill so unissued pool space holds zeros.
        unsafe { memsec::memzero(ptr.as_ptr(), bytes) };
        let inner = Arc::new(ArenaInner {
            ptr,
            cap: bytes,
            state: Mutex::new(ArenaState {
                offset: 0,
                live: 0,
                exposures: 0,
            }),
        });
        // Seal after `inner` exists so a (practically impossible) mprotect
        // panic still zeroizes + frees via ArenaInner::drop.
        protect(inner.ptr, memsec::Prot::NoAccess);
        Ok(SecretArena { inner })
    }

    pub fn try_alloc_from_slice(&self, src: &[u8]) -> Result<SecretBytes, MemError> {
        let offset = self.inner.reserve(src.len())?;
        {
            self.inner.begin_exposure();
            let _guard = ArenaExposureGuard(&self.inner);
            // SAFETY: region ReadWrite (exposure); `[offset, offset+len)` was
            // just reserved for this call alone, so nothing aliases it; src
            // is outside the pool.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    src.as_ptr(),
                    self.inner.ptr.as_ptr().add(offset),
                    src.len(),
                )
            };
        }
        Ok(SecretBytes {
            repr: Repr::Arena(ArenaRef {
                inner: Arc::clone(&self.inner),
                offset,
                len: src.len(),
            }),
        })
    }

    pub fn try_alloc_zeroed(&self, len: usize) -> Result<SecretBytes, MemError> {
        let offset = self.inner.reserve(len)?;
        // Pool space is zero on creation and re-zeroized on every release,
        // but zero explicitly anyway — defense in depth, not an invariant
        // chain.
        self.inner.zeroize_range(offset, len);
        Ok(SecretBytes {
            repr: Repr::Arena(ArenaRef {
                inner: Arc::clone(&self.inner),
                offset,
                len,
            }),
        })
    }

    /// Locked-page footprint of the pool region (page-rounded), for budget
    /// accounting against RLIMIT_MEMLOCK.
    pub fn locked_bytes(&self) -> usize {
        locked_span(self.inner.cap)
    }

    /// Test-only: read raw pool bytes to observe zero-on-drop of issued
    /// ranges. Never compiled into non-test builds.
    #[cfg(test)]
    fn test_read_raw(&self, offset: usize, len: usize) -> Vec<u8> {
        assert!(offset + len <= self.inner.cap);
        self.inner.begin_exposure();
        let _guard = ArenaExposureGuard(&self.inner);
        // SAFETY: region readable (exposure); bounds asserted above.
        unsafe { core::slice::from_raw_parts(self.inner.ptr.as_ptr().add(offset), len) }.to_vec()
    }
}

impl std::fmt::Debug for SecretArena {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretArena(<redacted>)")
    }
}

// ---------------------------------------------------------------------------
// mlock probing & budget
// ---------------------------------------------------------------------------

/// Probes the raw `libc::mlock` return code on a scratch page and, on Linux,
/// `VmLck` in `/proc/self/status` — NEVER the allocator backend's internal
/// success claim, which c23 showed can lie (memsec swallows the rc).
pub fn mlock_supported() -> bool {
    let page = page_size();
    // SAFETY: fresh anonymous private mapping of one page; no caller memory
    // involved.
    let ptr = unsafe {
        libc::mmap(
            core::ptr::null_mut(),
            page,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANON,
            -1,
            0,
        )
    };
    if ptr == libc::MAP_FAILED {
        return false;
    }
    // SAFETY: ptr maps exactly `page` bytes (just created above).
    let rc = unsafe { libc::mlock(ptr, page) };
    #[cfg(not(target_os = "linux"))]
    let ok = rc == 0;
    #[cfg(target_os = "linux")]
    // Positive assertion that locking *happened*: the kernel's own VmLck
    // accounting must be nonzero while our probe page is locked. If /proc is
    // unavailable, fall back to the raw rc.
    let ok = rc == 0 && vmlck_kb().map(|kb| kb > 0).unwrap_or(true);
    // SAFETY: same mapping as above; munlock before unmapping, then release.
    unsafe {
        if rc == 0 {
            libc::munlock(ptr, page);
        }
        libc::munmap(ptr, page);
    }
    ok
}

#[cfg(target_os = "linux")]
fn vmlck_kb() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmLck:") {
            return rest.trim().trim_end_matches("kB").trim().parse().ok();
        }
    }
    None
}

/// Process hardening (plan/03-memory §3.4, phase P0): unconditional
/// `setrlimit(RLIMIT_CORE, {0,0})` in ALL build profiles on both platforms
/// (macOS has no `MADV_DONTDUMP`, so RLIMIT_CORE is the only core control
/// there), and on Linux `prctl(PR_SET_DUMPABLE, 0)` before the first decrypt
/// — blocks `ptrace(PTRACE_ATTACH)` and `process_vm_readv` from non-root
/// same-UID processes regardless of `kernel.yama.ptrace_scope`.
///
/// Additive over the frozen §4.2 surface (like `try_from_string`): the plan
/// places these calls "in `main()` of daemon and CLI", and this is the sole
/// crate permitted `unsafe`, so the raw libc calls live here. Both operations
/// are infallible in practice (lowering RLIMIT_CORE to zero needs no
/// privilege; PR_SET_DUMPABLE(0) takes no pointers); return codes are
/// debug-asserted so a regression is loud under test.
pub fn harden_process() {
    let rl = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: setrlimit only reads the valid, owned `rl` struct.
    let rc = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &rl) };
    debug_assert_eq!(rc, 0, "setrlimit(RLIMIT_CORE, {{0,0}}) failed");

    #[cfg(target_os = "linux")]
    {
        // SAFETY: prctl(PR_SET_DUMPABLE, 0) takes no pointers and cannot
        // touch caller memory.
        let rc = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
        debug_assert_eq!(rc, 0, "prctl(PR_SET_DUMPABLE, 0) failed");
    }
}

/// Snapshot of the process memlock budget (plan/03-memory §3.5).
#[derive(Debug, Clone, Copy)]
pub struct LockBudget {
    /// `None` = RLIM_INFINITY.
    pub limit_bytes: Option<u64>,
    /// Bytes locked through this crate's allocations (advisory accounting;
    /// other libraries' locked pages are not visible here).
    pub locked_bytes: u64,
    pub page_size: usize,
}

/// Daemon startup check: budget must cover the vault size, fail closed.
pub fn lock_budget() -> Result<LockBudget, MemError> {
    let limit_bytes = memlock_limit()?;
    Ok(LockBudget {
        limit_bytes,
        locked_bytes: LOCKED_BYTES.load(Ordering::SeqCst),
        page_size: page_size(),
    })
}

// ---------------------------------------------------------------------------
// Tests (std only — no dev-dependencies)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposure_round_trip() {
        let mut s = SecretBytes::try_from_slice(b"correct horse battery staple").unwrap();
        assert_eq!(s.len(), 28);
        assert!(!s.is_empty());
        s.with_exposed(|b| assert_eq!(b, b"correct horse battery staple"));
        s.with_exposed_mut(|b| b[..7].copy_from_slice(b"CORRECT"));
        s.with_exposed(|b| assert_eq!(&b[..7], b"CORRECT"));
        // Repeated exposure still works (region re-protected in between).
        s.with_exposed(|b| assert_eq!(b.len(), 28));
    }

    #[test]
    fn nested_read_exposure() {
        let s = SecretBytes::try_from_slice(b"nest").unwrap();
        s.with_exposed(|outer| {
            s.with_exposed(|inner| assert_eq!(outer, inner));
            // Inner exposure ending must not re-protect the outer window.
            assert_eq!(outer, b"nest");
        });
    }

    #[test]
    fn debug_is_redacted() {
        let s = SecretBytes::try_from_slice(b"hunter2").unwrap();
        assert_eq!(format!("{s:?}"), "SecretBytes(<redacted>)");
        let arena = SecretArena::try_with_capacity(256).unwrap();
        let a = arena.try_alloc_from_slice(b"hunter2").unwrap();
        assert_eq!(format!("{a:?}"), "SecretBytes(<redacted>)");
        assert_eq!(format!("{arena:?}"), "SecretArena(<redacted>)");
        // And the redaction never contains the plaintext.
        assert!(!format!("{s:?}{a:?}").contains("hunter2"));
    }

    #[test]
    fn with_capacity_is_zero_filled() {
        let s = SecretBytes::try_with_capacity(64).unwrap();
        assert_eq!(s.len(), 64);
        s.with_exposed(|b| assert!(b.iter().all(|&x| x == 0)));
    }

    #[test]
    fn empty_secret() {
        let s = SecretBytes::try_with_capacity(0).unwrap();
        assert_eq!(s.len(), 0);
        assert!(s.is_empty());
        s.with_exposed(|b| assert!(b.is_empty()));
    }

    #[test]
    fn truncate_shrinks_and_zeroizes_tail() {
        let mut s = SecretBytes::try_from_slice(&[0xAA; 8]).unwrap();
        s.truncate(4);
        assert_eq!(s.len(), 4);
        s.with_exposed(|b| assert_eq!(b, &[0xAA; 4]));
        // The tail beyond the logical length must be zero in the buffer.
        let full = s.test_snapshot_capacity();
        assert_eq!(&full[..4], &[0xAA; 4]);
        assert_eq!(&full[4..8], &[0u8; 4]);
        // Growing truncate is a no-op.
        s.truncate(100);
        assert_eq!(s.len(), 4);
    }

    #[test]
    fn arena_truncate_zeroizes_tail() {
        let arena = SecretArena::try_with_capacity(256).unwrap();
        let mut a = arena.try_alloc_from_slice(&[0xCC; 16]).unwrap();
        a.truncate(10);
        assert_eq!(a.len(), 10);
        a.with_exposed(|b| assert_eq!(b, &[0xCC; 10]));
        // Bytes 10..16 of the reserved range are zero in the pool.
        assert_eq!(arena.test_read_raw(10, 6), vec![0u8; 6]);
    }

    #[test]
    fn arena_zero_on_drop_observable() {
        let arena = SecretArena::try_with_capacity(256).unwrap();
        let a = arena.try_alloc_from_slice(&[0xBB; 32]).unwrap();
        assert_eq!(arena.test_read_raw(0, 32), vec![0xBB; 32]);
        drop(a);
        // The dropped secret's range must be zeroized while the pool lives.
        assert_eq!(arena.test_read_raw(0, 32), vec![0u8; 32]);
    }

    #[test]
    fn from_string_zeroizes_source() {
        let mut src = String::from("api-key-abcdef0123456789");
        let ptr = src.as_ptr();
        let len = src.len();
        let s = SecretBytes::try_from_string(&mut src).unwrap();
        s.with_exposed(|b| assert_eq!(b, b"api-key-abcdef0123456789"));
        assert!(src.is_empty());
        // zeroize's String impl clears in place and retains capacity, so the
        // original buffer is still owned by `src` and readable here.
        assert!(src.capacity() >= len);
        // SAFETY: `src` is alive and its allocation (>= len bytes) was fully
        // initialized before being zeroized in place; reading it is defined.
        let residue = unsafe { core::slice::from_raw_parts(ptr, len) };
        assert!(
            residue.iter().all(|&b| b == 0),
            "source String not zeroized"
        );
    }

    #[test]
    fn arena_thousand_small_secrets_under_default_budget() {
        // 40 KiB pool: even at 16 KiB pages this is a 3-page (48 KiB) locked
        // span — inside the worst-case 64 KiB RLIMIT_MEMLOCK (plan/03 §3.5).
        let arena = SecretArena::try_with_capacity(40 * 1024).unwrap();
        assert!(arena.locked_bytes() >= 40 * 1024);
        let mut secrets = Vec::with_capacity(1000);
        for i in 0..1000u32 {
            let material = [(i % 251) as u8; 32];
            secrets.push(arena.try_alloc_from_slice(&material).unwrap());
        }
        for (i, s) in secrets.iter().enumerate() {
            s.with_exposed(|b| {
                assert_eq!(b.len(), 32);
                assert!(b.iter().all(|&x| x == (i as u32 % 251) as u8));
            });
        }
        drop(secrets);
        // Everything released -> bump offset reset -> a second full wave fits.
        let mut wave2 = Vec::with_capacity(1000);
        for _ in 0..1000 {
            wave2.push(arena.try_alloc_zeroed(32).unwrap());
        }
        wave2[999].with_exposed(|b| assert!(b.iter().all(|&x| x == 0)));
    }

    #[test]
    fn arena_exhaustion_is_typed() {
        let arena = SecretArena::try_with_capacity(64).unwrap();
        let _a = arena.try_alloc_zeroed(48).unwrap();
        match arena.try_alloc_zeroed(32) {
            Err(MemError::LockExhausted {
                locked_bytes,
                limit_bytes,
            }) => {
                assert_eq!(locked_bytes, 48);
                assert_eq!(limit_bytes, 64);
            }
            other => panic!("expected LockExhausted, got {other:?}"),
        }
        // Exactly-fitting remainder still succeeds.
        let _b = arena.try_alloc_zeroed(16).unwrap();
    }

    #[test]
    fn mlock_supported_is_sane_and_stable() {
        let first = mlock_supported();
        let second = mlock_supported();
        assert_eq!(first, second, "mlock_supported() must be deterministic");
        // If locked constructors work in this process, the probe must agree.
        if SecretBytes::try_from_slice(b"probe").is_ok() {
            assert!(first, "allocations lock, but mlock_supported() says no");
        }
    }

    #[test]
    fn try_random_is_unique_across_calls() {
        let a = SecretBytes::try_random(32).unwrap();
        let b = SecretBytes::try_random(32).unwrap();
        assert_eq!(a.len(), 32);
        let av = a.with_exposed(|x| x.to_vec());
        let bv = b.with_exposed(|x| x.to_vec());
        assert_ne!(av, bv, "two 32-byte random draws collided");
        assert!(av.iter().any(|&x| x != 0), "random draw was all zeros");
    }

    #[test]
    fn lock_budget_reports_sane_values() {
        let budget = lock_budget().unwrap();
        assert!(budget.page_size.is_power_of_two());
        assert!(budget.page_size >= 4096);
        // Hold a live secret and confirm accounting is visibly nonzero.
        let _s = SecretBytes::try_from_slice(&[1u8; 128]).unwrap();
        let after = lock_budget().unwrap();
        assert!(after.locked_bytes > 0);
    }

    #[test]
    fn zero_length_arena_alloc() {
        let arena = SecretArena::try_with_capacity(16).unwrap();
        let s = arena.try_alloc_from_slice(b"").unwrap();
        assert!(s.is_empty());
        s.with_exposed(|b| assert!(b.is_empty()));
    }

    #[test]
    fn exposure_survives_closure_panic() {
        let s = SecretBytes::try_from_slice(b"panic-safety").unwrap();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            s.with_exposed(|_| panic!("boom"));
        }));
        assert!(result.is_err());
        // Guard re-protected on unwind; the secret is still usable.
        s.with_exposed(|b| assert_eq!(b, b"panic-safety"));
    }
}
