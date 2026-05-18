use core::mem::MaybeUninit;

use crate::ffi::stomach_cp_cache;

pub use crate::ffi::stomach_cp_cache::{
    StomachCpCacheRaw, STOMACH_CP_CACHE_SIZE, STOMACH_CP_DIGEST_LEN,
};

pub struct StomachCpCache {
    raw: StomachCpCacheRaw,
}

impl StomachCpCache {
    pub const CAPACITY: usize = STOMACH_CP_CACHE_SIZE;

    pub fn new() -> Self {
        Self { raw: new_raw() }
    }

    pub fn clear(&mut self) {
        clear(&mut self.raw);
    }

    pub fn contains(&self, digest: &[u8; STOMACH_CP_DIGEST_LEN]) -> bool {
        contains(&self.raw, digest)
    }

    pub fn seen_or_add(&mut self, digest: &[u8; STOMACH_CP_DIGEST_LEN]) -> bool {
        seen_or_add(&mut self.raw, digest)
    }

    pub fn count(&self) -> usize {
        count(&self.raw)
    }

    pub fn as_raw(&self) -> &StomachCpCacheRaw {
        &self.raw
    }

    pub fn as_raw_mut(&mut self) -> &mut StomachCpCacheRaw {
        &mut self.raw
    }
}

impl Default for StomachCpCache {
    fn default() -> Self {
        Self::new()
    }
}

pub fn new_raw() -> StomachCpCacheRaw {
    let mut cache = MaybeUninit::<StomachCpCacheRaw>::uninit();
    unsafe {
        stomach_cp_cache::stomach_cp_cache_init(cache.as_mut_ptr());
        cache.assume_init()
    }
}

pub fn init(cache: &mut StomachCpCacheRaw) {
    unsafe { stomach_cp_cache::stomach_cp_cache_init(cache) };
}

pub fn clear(cache: &mut StomachCpCacheRaw) {
    unsafe { stomach_cp_cache::stomach_cp_cache_clear(cache) };
}

pub fn contains(cache: &StomachCpCacheRaw, digest: &[u8; STOMACH_CP_DIGEST_LEN]) -> bool {
    unsafe { stomach_cp_cache::stomach_cp_cache_contains(cache, digest.as_ptr()) }
}

pub fn seen_or_add(cache: &mut StomachCpCacheRaw, digest: &[u8; STOMACH_CP_DIGEST_LEN]) -> bool {
    unsafe { stomach_cp_cache::stomach_cp_cache_seen_or_add(cache, digest.as_ptr()) }
}

pub fn count(cache: &StomachCpCacheRaw) -> usize {
    unsafe { stomach_cp_cache::stomach_cp_cache_count(cache) }
}
