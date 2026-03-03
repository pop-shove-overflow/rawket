#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

// In no_std mode the alloc crate must be brought in explicitly.
// In std mode alloc is part of the standard library and accessible
// as a crate path without an explicit extern crate declaration, but
// including one here is harmless and keeps downstream `use alloc::…`
// imports working uniformly across both build modes.
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
pub mod af_packet;
pub mod tcp;
pub mod timers;
pub mod udp;

pub use network::{Network, NetworkConfig, Uplink};
pub use af_packet::AfPacketSocket;

// ── no_std runtime ────────────────────────────────────────────────────────────
//
// When the `std` feature is disabled rawket is fully self-contained: it
// provides its own global allocator (libc malloc/free) and panic handler
// (abort).  When `std` is enabled these are supplied by the Rust runtime
// and must not be redefined here.

/// Shared TX-path closure type used by interfaces and sockets.
pub(crate) type TxFn = alloc::rc::Rc<dyn Fn(&[u8]) -> Result<()>>;

#[cfg(not(feature = "std"))]
mod rt {
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

    #[panic_handler]
    fn panic(_info: &core::panic::PanicInfo) -> ! {
        unsafe { libc::abort() }
    }
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
