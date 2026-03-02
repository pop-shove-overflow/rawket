#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

extern crate alloc;
extern crate libc;

pub mod arp;
pub mod arp_cache;
pub mod eth;
pub mod ffi;
pub mod icmp;
pub mod interface;
pub mod ip;
pub mod network;
pub mod packet_socket;
pub mod raw_socket;
pub mod tcp;
pub mod timers;
pub mod udp;

pub use network::{Network, NetworkConfig, Uplink};
pub use packet_socket::PacketSocket;

// ── Global allocator (libc malloc/free) ──────────────────────────────────────

use core::alloc::{GlobalAlloc, Layout};

struct LibcAllocator;

unsafe impl GlobalAlloc for LibcAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { libc::malloc(layout.size()) as *mut u8 }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        unsafe { libc::free(ptr as *mut libc::c_void) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, _layout: Layout, new_size: usize) -> *mut u8 {
        unsafe { libc::realloc(ptr as *mut libc::c_void, new_size) as *mut u8 }
    }
}

#[global_allocator]
static ALLOCATOR: LibcAllocator = LibcAllocator;

// ── Panic handler ─────────────────────────────────────────────────────────────

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { libc::abort() }
}

// ── Error type ────────────────────────────────────────────────────────────────

/// Slim error type used throughout rawket (no heap allocation).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// OS error with raw errno value.
    Os(i32),
    /// Received packet was malformed or unexpected.
    InvalidData,
    /// Caller passed bad arguments.
    InvalidInput,
    /// TX ring full or RX ring empty (retry).
    WouldBlock,
    /// Operation requires an established connection.
    NotConnected,
}

impl Error {
    /// Capture the current `errno` value.
    pub fn last_os() -> Self {
        Self::Os(unsafe { *libc::__errno_location() })
    }

    /// Return the raw errno if this is an `Os` variant.
    pub fn raw_os(&self) -> Option<i32> {
        if let Self::Os(e) = self { Some(*e) } else { None }
    }
}

pub type Result<T> = core::result::Result<T, Error>;
