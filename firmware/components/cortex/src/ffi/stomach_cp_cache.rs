pub const STOMACH_CP_CACHE_SIZE: usize = 16;
pub const STOMACH_CP_DIGEST_LEN: usize = 32;

const _: () = assert!(STOMACH_CP_CACHE_SIZE > 0);

#[repr(C)]
pub struct StomachCpCacheRaw {
    pub entries: [[u8; STOMACH_CP_DIGEST_LEN]; STOMACH_CP_CACHE_SIZE],
    pub next: usize,
    pub count: usize,
}

unsafe extern "C" {
    pub fn stomach_cp_cache_init(cache: *mut StomachCpCacheRaw);
    pub fn stomach_cp_cache_clear(cache: *mut StomachCpCacheRaw);
    pub fn stomach_cp_cache_contains(cache: *const StomachCpCacheRaw, digest: *const u8) -> bool;
    pub fn stomach_cp_cache_seen_or_add(cache: *mut StomachCpCacheRaw, digest: *const u8) -> bool;
    pub fn stomach_cp_cache_count(cache: *const StomachCpCacheRaw) -> usize;
}
