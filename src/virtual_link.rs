/// In-process virtual Ethernet link for testing.
///
/// A [`VirtualLink`] implements [`EtherLink`] without any OS file descriptors.
/// Two links can be wired together with [`connect`] so that each link's
/// `tx_send` pushes frames into the peer's RX queue.
///
/// Construction is peerless: [`VirtualLink::new`] creates a disconnected link.
/// Call [`connect`] after both sides exist.
use alloc::{collections::VecDeque, rc::Rc, vec::Vec};
use core::cell::RefCell;
use crate::{af_packet::EtherLink, Result, TxFn};

/// Maximum frames buffered in a single RX queue before `tx_send` returns
/// `WouldBlock`.  Prevents unbounded memory growth in tests that transmit
/// without polling the receiver.
const MAX_QUEUE_DEPTH: usize = 256;

type Queue = Rc<RefCell<VecDeque<Vec<u8>>>>;

/// An in-process Ethernet endpoint.
///
/// Frames sent via [`tx_send`](EtherLink::tx_send) are delivered to the peer's
/// RX queue (if connected).  Frames are read back via
/// [`rx_recv`](EtherLink::rx_recv) / [`rx_release`](EtherLink::rx_release).
pub struct VirtualLink {
    /// Frames waiting for this link's owner to read.
    rx_queue: Queue,
    /// Peer's RX queue — `None` until [`connect`] is called.
    peer_rx:  Option<Queue>,
    /// Scratch buffer holding the frame currently lent out by `rx_recv`.
    rx_buf:   Vec<u8>,
}

impl Default for VirtualLink {
    fn default() -> Self { Self::new() }
}

impl VirtualLink {
    /// Create a disconnected virtual link.
    ///
    /// The link has its own RX queue but no peer.  Call [`connect`] to wire
    /// two links together.
    pub fn new() -> Self {
        VirtualLink {
            rx_queue: Rc::new(RefCell::new(VecDeque::new())),
            peer_rx:  None,
            rx_buf:   Vec::new(),
        }
    }

    /// Return a handle to this link's RX queue (used by [`connect`]).
    fn rx_handle(&self) -> Queue {
        self.rx_queue.clone()
    }
}

/// Wire two virtual links together so that A's TX feeds B's RX and vice versa.
///
/// Can be called multiple times to rewire (e.g. after inserting a middlebox),
/// but each link can have at most one peer at a time.
pub fn connect(a: &mut VirtualLink, b: &mut VirtualLink) {
    let a_rx = a.rx_handle();
    let b_rx = b.rx_handle();
    a.peer_rx = Some(b_rx);
    b.peer_rx = Some(a_rx);
}

impl EtherLink for VirtualLink {
    fn rx_recv(&mut self) -> Option<&[u8]> {
        let frame = self.rx_queue.borrow_mut().pop_front()?;
        self.rx_buf = frame;
        Some(&self.rx_buf)
    }

    fn rx_release(&mut self) {
        // Nothing to do — `rx_buf` will be overwritten on next `rx_recv`.
    }

    fn tx_send(&mut self, frame: &[u8]) -> Result<()> {
        let peer = self.peer_rx.as_ref().ok_or(crate::Error::NotConnected)?;
        let mut q = peer.borrow_mut();
        if q.len() >= MAX_QUEUE_DEPTH {
            return Err(crate::Error::WouldBlock);
        }
        q.push_back(frame.to_vec());
        Ok(())
    }

    fn open_tx(&self) -> Result<TxFn> {
        let peer = self.peer_rx.clone().ok_or(crate::Error::NotConnected)?;
        Ok(Rc::new(move |frame: &[u8]| {
            let mut q = peer.borrow_mut();
            if q.len() >= MAX_QUEUE_DEPTH {
                return Err(crate::Error::WouldBlock);
            }
            q.push_back(frame.to_vec());
            Ok(())
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disconnected_tx_returns_not_connected() {
        let mut link = VirtualLink::new();
        let err = link.tx_send(b"hello").unwrap_err();
        assert_eq!(err, crate::Error::NotConnected);
    }

    #[test]
    fn connected_pair_delivers_frames() {
        let mut a = VirtualLink::new();
        let mut b = VirtualLink::new();
        connect(&mut a, &mut b);

        a.tx_send(b"frame_a_to_b").unwrap();
        b.tx_send(b"frame_b_to_a").unwrap();

        let rx_b = b.rx_recv().unwrap();
        assert_eq!(rx_b, b"frame_a_to_b");
        b.rx_release();

        let rx_a = a.rx_recv().unwrap();
        assert_eq!(rx_a, b"frame_b_to_a");
        a.rx_release();
    }

    #[test]
    fn rx_recv_returns_none_when_empty() {
        let mut a = VirtualLink::new();
        let mut b = VirtualLink::new();
        connect(&mut a, &mut b);
        assert!(b.rx_recv().is_none());
    }

    #[test]
    fn open_tx_delivers_via_closure() {
        let mut a = VirtualLink::new();
        let mut b = VirtualLink::new();
        connect(&mut a, &mut b);

        let tx = a.open_tx().unwrap();
        tx(b"from_closure").unwrap();

        let rx = b.rx_recv().unwrap();
        assert_eq!(rx, b"from_closure");
    }

    #[test]
    fn queue_overflow_returns_would_block() {
        let mut a = VirtualLink::new();
        let mut b = VirtualLink::new();
        connect(&mut a, &mut b);

        for _ in 0..MAX_QUEUE_DEPTH {
            a.tx_send(b"x").unwrap();
        }
        let err = a.tx_send(b"overflow").unwrap_err();
        assert_eq!(err, crate::Error::WouldBlock);
    }
}
