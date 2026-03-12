use rawket::tcp::{State, TcpConfig, TcpFlags, TcpSocket};
use crate::{
    assert::{assert_timestamps_present, assert_state, TestFail},
    assert_ok,
    capture::ParsedFrameExt,
    harness::{setup_network_pair, setup_tcp_pair},
    packet::{build_tcp_data, build_tcp_data_with_ts, build_tcp_syn},
    TestResult,
};

// RFC 7323 §3.2 (Timestamps Negotiation): Both sides use default TcpConfig.
// SYN and SYN-ACK must carry Timestamps.
#[test]
fn negotiation() -> TestResult {
    use rawket::bridge::LinkProfile;
    let (_pair, cap) = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect_and_capture();

    let syn = cap.tcp().from_a()
        .with_tcp_flags(TcpFlags::SYN)
        .without_tcp_flags(TcpFlags::ACK)
        .next()
        .ok_or_else(|| TestFail::new("no SYN from A"))?;

    let syn_ack = cap.tcp().from_b()
        .with_tcp_flags(TcpFlags::SYN)
        .with_tcp_flags(TcpFlags::ACK)
        .next()
        .ok_or_else(|| TestFail::new("no SYN-ACK from B"))?;

    assert_timestamps_present(&syn,     "SYN timestamps")?;
    assert_timestamps_present(&syn_ack, "SYN-ACK timestamps")?;

    // SYN: TSecr must be 0 (no peer timestamp to echo yet).
    let (syn_tsval, syn_tsecr) = syn.tcp.opts.timestamps.unwrap();
    assert_ok!(syn_tsecr == 0, "SYN TSecr should be 0 but got {syn_tsecr}");
    assert_ok!(syn_tsval > 0,  "SYN TSval should be non-zero");

    // SYN-ACK: TSval must be > 0, TSecr must echo SYN's TSval.
    let (sa_tsval, sa_tsecr) = syn_ack.tcp.opts.timestamps.unwrap();
    assert_ok!(sa_tsval > 0, "SYN-ACK TSval should be non-zero");
    assert_ok!(
        sa_tsecr == syn_tsval,
        "SYN-ACK TSecr should echo SYN TSval ({syn_tsval}), got {sa_tsecr}"
    );

    // Third ACK (handshake completion) must also carry timestamps.
    let third_ack = cap.tcp().from_a()
        .with_tcp_flags(TcpFlags::ACK)
        .without_tcp_flags(TcpFlags::SYN)
        .next()
        .ok_or_else(|| TestFail::new("no third ACK from A"))?;
    assert_timestamps_present(&third_ack, "third ACK timestamps")?;

    // Third ACK TSecr must echo SYN-ACK's TSval.
    let (_, ack_tsecr) = third_ack.tcp.opts.timestamps.unwrap();
    assert_ok!(
        ack_tsecr == sa_tsval,
        "third ACK TSecr should echo SYN-ACK TSval ({sa_tsval}), got {ack_tsecr}"
    );

    Ok(())
}

// RFC 7323 §4.1 (RTT Measurement): B's ACK for A's data must echo A's TSval
// in its TSecr.
#[test]
fn ts_ecr_reflects_tsval() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    pair.tcp_a_mut().send(b"x")?;
    pair.transfer();

    let cap2 = pair.drain_captured();
    let a_tsval = cap2.tcp().from_a().with_data()
        .find_map(|f| f.tcp.opts.timestamps.map(|(v, _)| v))
        .ok_or_else(|| TestFail::new("no timestamps in A's data frame"))?;
    let b_tsecr = cap2.tcp().from_b()
        .with_tcp_flags(TcpFlags::ACK)
        .find_map(|f| f.tcp.opts.timestamps.map(|(_, ecr)| ecr))
        .ok_or_else(|| TestFail::new("no timestamped ACK from B"))?;

    assert_ok!(
        b_tsecr == a_tsval,
        "B's TSecr ({b_tsecr}) should equal A's TSval ({a_tsval})"
    );

    Ok(())
}

// RFC 7323 §3.2 (Timestamps Negotiation): When client SYN has no TS option,
// server must not use timestamps on data.
#[test]
fn ts_disabled_if_peer_omits() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut np = setup_network_pair()
        .profile(LinkProfile::leased_line_100m());
    let cfg = TcpConfig::default();

    let server = TcpSocket::accept(
        np.iface_b(),
        "10.0.0.2:80".parse().unwrap(),
        |_| {}, |_| {},
        cfg,
    )?;
    np.add_tcp_b(server);

    // Inject SYN without Timestamps option.
    let isn_a = 0x3000_0000u32;
    let syn = build_tcp_syn(
        np.mac_a, np.mac_b,
        np.ip_a,  np.ip_b,
        12345, 80,
        isn_a, 0,
        0x02,
        Some(1460), None, None, false,
    );
    np.inject_to_b(syn);
    np.transfer_one();

    let cap = np.drain_captured();
    let syn_ack = cap.tcp().from_b()
        .with_tcp_flags(TcpFlags::SYN)
        .with_tcp_flags(TcpFlags::ACK)
        .next()
        .ok_or_else(|| TestFail::new("no SYN-ACK from B"))?;

    let ack = build_tcp_data(
        np.mac_a, np.mac_b,
        np.ip_a,  np.ip_b,
        12345, 80,
        isn_a + 1,
        syn_ack.tcp.seq + 1,
        &[],
    );
    np.inject_to_b(ack);
    np.transfer_one();

    assert_state(np.tcp_b(0), State::Established, "B state after handshake without peer TS")?;
    np.clear_capture();

    // Push data from B; data frames must not carry TS options.
    let big = vec![0xabu8; 500];
    np.tcp_b_mut(0).send(&big)?;

    let cap = np.drain_captured();
    let has_ts = cap.tcp().from_b().with_data().any(|f| f.tcp.opts.timestamps.is_some());
    assert_ok!(
        !has_ts,
        "B sent data frames with Timestamps option despite peer omitting TS"
    );

    Ok(())
}

// RFC 7323 §5.3 R1: segment with stale TSval (and RST not set) is treated
// as not acceptable — "Send an acknowledgment in reply... and drop the
// segment."
#[test]
fn paws_drop_stale() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    pair.tcp_a_mut().send(b"x")?;
    pair.transfer();

    let cap = pair.drain_captured();
    let af = cap.tcp().from_a().with_data().next()
        .ok_or_else(|| TestFail::new("no AtoB data frame"))?;
    let a_ts_val = af.tcp.opts.timestamps.map(|(v, _)| v).unwrap_or(0);
    // B's rcv_nxt = af.tcp.seq + af.payload_len
    let b_rcv_nxt = af.tcp.seq + af.payload_len as u32;

    // B's snd_nxt = SYN-ACK seq + 1
    let b_snd_nxt = cap.all_tcp().from_b()
        .with_tcp_flags(TcpFlags::SYN)
        .last()
        .map(|f| f.tcp.seq.wrapping_add(1))
        .unwrap_or(0);

    let ts_recent_before = pair.tcp_b().ts_recent();
    pair.clear_capture();

    // Inject NEW in-order data at B's rcv_nxt with a STALE TSval.
    let stale = build_tcp_data_with_ts(
        pair.mac_a, pair.mac_b,
        pair.ip_a,  pair.ip_b,
        12345, 80,
        b_rcv_nxt,                    // new data at rcv_nxt
        b_snd_nxt,
        a_ts_val.wrapping_sub(1000),  // stale TSval
        0,
        b"y",
    );
    pair.inject_to_b(stale);
    pair.transfer_one();

    // B must NOT advance rcv_nxt — segment was dropped by PAWS.
    let rcv_nxt_after = pair.tcp_b().rcv_nxt();
    assert_ok!(
        rcv_nxt_after == b_rcv_nxt,
        "B's rcv_nxt advanced ({b_rcv_nxt} → {rcv_nxt_after}) — PAWS did not drop the segment"
    );

    // RFC 7323 §5.3 R1: "Send an acknowledgment in reply... and drop the segment."
    // The ACK must be a duplicate ACK with ack == rcv_nxt (unchanged).
    let cap = pair.drain_captured();
    let ack_frame = cap.tcp().from_b()
        .with_tcp_flags(TcpFlags::ACK)
        .without_tcp_flags(TcpFlags::SYN)
        .next()
        .ok_or_else(|| TestFail::new("B did not send ACK in response to PAWS-dropped segment"))?;
    assert_ok!(
        ack_frame.tcp.ack == b_rcv_nxt,
        "B's PAWS ACK ({}) != rcv_nxt ({b_rcv_nxt}) — should be duplicate ACK",
        ack_frame.tcp.ack
    );

    // ts_recent must NOT be updated by the stale segment.
    let ts_recent_after = pair.tcp_b().ts_recent();
    assert_ok!(
        ts_recent_after == ts_recent_before,
        "ts_recent changed from {ts_recent_before} to {ts_recent_after} after PAWS-dropped segment"
    );

    Ok(())
}
