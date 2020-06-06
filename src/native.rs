use libc::{c_void, malloc, free, c_int, c_uint};
use std::ptr::null_mut;
use std::mem::size_of;


#[allow(non_upper_case_globals)]
const md6_c: usize = 16;
#[allow(non_upper_case_globals)]
const md6_w: usize = 64;
#[allow(non_upper_case_globals)]
const md6_k: usize = 8;
#[allow(non_upper_case_globals)]
const md6_b: usize = 64;
#[allow(non_upper_case_globals)]
const md6_max_stack_height: usize = 29;

#[allow(non_snake_case)]
#[repr(C)]
struct md6_state {
    d: c_int,
    hashbitlen: c_int,
    hashval: [u8; md6_c * (md6_w / 8)],
    hexhashval: [u8; (md6_c * (md6_w / 8)) + 1],
    initialized: c_int,
    bits_processed: u64,
    compression_calls: u64,
    finalized: c_int,
    K: [u64; md6_k],
    keylen: c_int,
    L: c_int,
    r: c_int,
    top: c_int,
    B: [[u64; md6_max_stack_height]; md6_b],
    bits: [c_uint; md6_max_stack_height],
    i_for_level: [u64; md6_max_stack_height],
}


pub type FFIHashState = *mut c_void;


#[link(name = "md6")]
extern "C" {
    pub fn MD6_Hash_Init(state: FFIHashState, hashbitlen: c_int) -> c_int;
    pub fn MD6_Hash_Update(state: FFIHashState, data: *const u8, databitlen: u64) -> c_int;
    pub fn MD6_Hash_Final(state: FFIHashState, hashval: *mut u8) -> c_int;

    pub fn MD6_Hash_Hash(hashbitlen: c_int, data: *const u8, databitlen: u64, hashval: *mut u8) -> c_int;
}

pub fn malloc_hash_state() -> FFIHashState {
    unsafe { malloc(size_of::<md6_state>()) }
}

pub fn free_hash_state(state: &mut FFIHashState) {
    unsafe { free(*state) };
    *state = null_mut();
}
