use rawket::{
    bridge::{Impairment, LinkProfile, PacketSpec},
    filter,
    tcp::{State, TcpError, TcpSocket},
};
use crate::{
    assert::{assert_error_fired, assert_gap_approx, assert_state, assert_timestamps_present, TestFail},
    assert_ok,
    capture::ParsedFrameExt,
    harness::{fast_tcp_cfg, setup_network_pair, setup_tcp_pair},
    packet::build_tcp_data,
    TestResult,
};
use std::net::Ipv4Addr;

// RFC 6298 §5: RTO timer fires when no ACK arrives within the computed
// timeout.  Use an instant link so SRTT stays 0 after handshake — TLP
// requires SRTT > 0 (our implementation choice), so only RTO can fire.
// Drop first frame; verify the retransmit fires at approximately rto_min.
#[test]
fn initial_rto() -> TestResult {
    // Instant link: SRTT stays 0 after handshake, so TLP won't arm
    // (our implementation requires SRTT > 0).  Only RTO can fire.
    let mut pair = setup_tcp_pair().connect();

    assert_ok!(pair.tcp_a().srtt_ms() == 0, "SRTT should be 0 on instant link");

    // Drop first data frame.
    pair.add_impairment_to_b(Impairment::Drop(PacketSpec::nth_matching(1, filter::tcp::has_data())));
    pair.tcp_a_mut().send(b"hello")?;

    let rto = pair.tcp_a().rto_ms();
    pair.transfer();

    let cap = pair.drain_captured();
    let orig = cap.all_tcp().from_a().dropped().with_data().next()
        .ok_or_else(|| TestFail::new("no dropped AtoB data frame"))?;
    let retx = cap.all_tcp().from_a().delivered().with_data()
        .find(|f| f.tcp.seq == orig.tcp.seq)
        .ok_or_else(|| TestFail::new("no retransmitted AtoB data frame"))?;

    // RFC 6298 §5: retransmit gap should match the RTO value (±30%).
    let gap = retx.ms_since(&orig);
    assert_ok!(
        gap >= rto * 7 / 10 && gap <= rto * 13 / 10,
        "retransmit gap {gap}ms not ≈ RTO ({rto}ms) [expected {}-{}]",
        rto * 7 / 10, rto * 13 / 10
    );

    Ok(())
}
