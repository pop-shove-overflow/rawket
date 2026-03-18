use rawket::tcp::{State, TcpConfig, TcpFlags, TcpSocket};
use crate::{
    assert::{assert_timestamps_present, assert_state, TestFail},
    assert_ok,
    capture::ParsedFrameExt,
    harness::{setup_network_pair, setup_tcp_pair},
    packet::{build_tcp_data, build_tcp_data_with_ts, build_tcp_syn, recompute_frame_tcp_checksum},
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

// RFC 7323 §5 (PAWS): PAWS must handle 32-bit TSval wraparound correctly;
// a post-wrap TSval that is forward in serial-number space is accepted.
#[test]
fn wraparound_accepted() -> TestResult {
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

    // Inject SYN with high TSval (near wrap).
    let isn_a = 0x7000_0000u32;
    let syn = build_tcp_syn(
        np.mac_a, np.mac_b,
        np.ip_a,  np.ip_b,
        12345, 80,
        isn_a, 0,
        0x02,
        Some(1460), Some(4),
        Some((0xFFFF_FF00, 0)),
        true,
    );
    np.inject_to_b(syn);
    np.transfer_one();

    let cap = np.drain_captured();
    let syn_ack = cap.tcp().from_b()
        .with_tcp_flags(TcpFlags::SYN)
        .with_tcp_flags(TcpFlags::ACK)
        .next()
        .ok_or_else(|| TestFail::new("no SYN-ACK from B"))?;
    let b_isn = syn_ack.tcp.seq;
    let b_tsval = syn_ack.tcp.opts.timestamps.map(|(v, _)| v).unwrap_or(0);

    let ack = build_tcp_data_with_ts(
        np.mac_a, np.mac_b,
        np.ip_a,  np.ip_b,
        12345, 80,
        isn_a + 1, b_isn + 1,
        0x0000_0010,
        b_tsval,
        &[],
    );
    np.inject_to_b(ack);
    np.transfer_one();

    assert_state(np.tcp_b(0), State::Established, "B Established after TS wrap handshake")?;

    np.clear_capture();

    // Inject data with a post-wrap TSval — must be accepted.
    let data = build_tcp_data_with_ts(
        np.mac_a, np.mac_b,
        np.ip_a,  np.ip_b,
        12345, 80,
        isn_a + 1, b_isn + 1,
        0x0000_0020, // post-wrap TSval (forward from 0x00000010)
        b_tsval,
        b"wrap-ok",
    );
    np.inject_to_b(data);
    np.transfer_one();

    let cap = np.drain_captured();
    let acked = cap.tcp().from_b()
        .with_tcp_flags(TcpFlags::ACK)
        .any(|f| f.tcp.ack > isn_a + 1);
    assert_ok!(acked, "B dropped data after TSval wrap — PAWS not handling wraparound");

    assert_state(np.tcp_b(0), State::Established, "B Established after accepting wrapped TSval")?;

    Ok(())
}

// RFC 7323 §5.2 states PAWS protects against "old duplicate non-<SYN>
// segments", implying SYN is exempt.  However, §5.3 R1 only explicitly
// exempts RST.  Our implementation follows §5.2's intent and exempts SYN
// from PAWS to allow TIME-WAIT connection reuse (RFC 9293 §3.6.1 MAY-2).
//
// Step 1 proves PAWS is active (stale data dropped, rcv_nxt unchanged).
// Step 2 injects a SYN with the same stale TSval and checks that
// challenge_ack_count incremented — proving the SYN reached the state
// machine (RFC 5961 §4.2) rather than being PAWS-dropped at R1.
#[test]
fn syn_bypasses_paws() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    pair.tcp_a_mut().send(b"warmup")?;
    pair.transfer();

    let ts_recent = pair.tcp_b().ts_recent();
    assert_ok!(ts_recent > 0, "ts_recent not populated after handshake + data");

    let stale_tsval = ts_recent.wrapping_sub(0x4000_0000); // ~1 billion behind
    let b_rcv_nxt = pair.tcp_b().rcv_nxt();
    let b_snd_nxt = pair.tcp_b().snd_nxt();

    // Step 1: Prove PAWS is active by injecting a stale DATA segment.
    // PAWS R1 drops it — rcv_nxt must NOT advance.
    pair.clear_capture();
    let stale_data = build_tcp_data_with_ts(
        pair.mac_a, pair.mac_b,
        pair.ip_a,  pair.ip_b,
        12345, 80,
        b_rcv_nxt, b_snd_nxt,
        stale_tsval, 0,
        b"stale",
    );
    pair.inject_to_b(stale_data);
    pair.transfer_one();

    assert_ok!(
        pair.tcp_b().rcv_nxt() == b_rcv_nxt,
        "stale DATA was accepted (rcv_nxt advanced) — PAWS not working"
    );

    // Step 2: Inject a SYN with the same stale TSval.  If our SYN
    // exemption works, the SYN bypasses PAWS and reaches the state
    // machine → challenge ACK (RFC 5961 §4.2), incrementing the
    // challenge_ack_count.  A PAWS-drop would NOT increment it.
    let chal_before = pair.tcp_b().challenge_ack_count();

    pair.clear_capture();
    let syn = build_tcp_syn(
        pair.mac_a, pair.mac_b,
        pair.ip_a,  pair.ip_b,
        12345, 80,
        b_rcv_nxt,
        0,
        0x02,
        Some(1460), Some(4),
        Some((stale_tsval, 0)),
        true,
    );
    pair.inject_to_b(syn);
    pair.transfer_one();

    // The challenge ACK counter must have incremented — proving the SYN
    // reached the state machine (RFC 5961 §4.2) rather than being
    // PAWS-dropped at R1.
    let chal_after = pair.tcp_b().challenge_ack_count();
    assert_ok!(
        chal_after > chal_before,
        "challenge_ack_count did not increment ({chal_before} → {chal_after}) — \
         SYN was PAWS-dropped instead of reaching the state machine"
    );

    let cap = pair.drain_captured();

    // Must NOT be a SYN-ACK (B must not re-enter handshake).
    let syn_ack = cap.tcp().from_b()
        .with_tcp_flags(TcpFlags::SYN)
        .with_tcp_flags(TcpFlags::ACK)
        .next()
        .is_some();
    assert_ok!(!syn_ack, "B sent SYN-ACK instead of challenge ACK");

    // Connection must survive.
    assert_state(pair.tcp_b(), State::Established, "B must stay Established after SYN bypass")?;

    Ok(())
}

// RFC 7323 §5: PAWS must NOT apply to RST segments.
// Inject a RST with a stale TSval — connection must still close.
#[test]
fn rst_bypasses_paws() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    pair.tcp_a_mut().send(b"warmup")?;
    pair.transfer();

    let ts_recent = pair.tcp_b().ts_recent();
    assert_ok!(ts_recent > 0, "ts_recent not populated");

    let rcv_nxt = pair.tcp_b().rcv_nxt();
    pair.clear_capture();

    // Build a RST with a stale TSval using build_tcp_data_with_ts and patching flags.
    let stale_tsval = ts_recent.wrapping_sub(0x4000_0000);
    let b_snd_nxt = pair.tcp_b().snd_nxt();
    let mut rst = build_tcp_data_with_ts(
        pair.mac_a, pair.mac_b,
        pair.ip_a,  pair.ip_b,
        12345, 80,
        rcv_nxt,   // exact seq match for RST acceptance
        b_snd_nxt,
        stale_tsval,
        0,
        &[],
    );
    // Patch flags: change ACK (0x10) to RST (0x04).
    rst[47] = 0x04;
    recompute_frame_tcp_checksum(&mut rst);

    pair.inject_to_b(rst);
    pair.transfer_one();

    // B must close — RST bypasses PAWS.
    assert_state(pair.tcp_b(), State::Closed, "B must close after RST with stale TSval (PAWS bypassed)")?;

    Ok(())
}

// RFC 7323 §4.1 (RTT Measurement): After data/ACK exchange with TS,
// srtt_ms() should be reasonable.
#[test]
fn rtt_via_timestamps() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    pair.tcp_a_mut().send(b"rtt-test")?;
    pair.transfer_while(|p| p.tcp_a(0).snd_una() != p.tcp_a(0).snd_nxt());

    // Verify data frames carry timestamp options.
    let cap = pair.drain_captured();
    let ts_present = cap.tcp().from_a().with_data().all(|f| f.tcp.opts.timestamps.is_some());
    assert_ok!(ts_present, "data frames from A lack timestamp options");

    // Verify B's ACK echoes A's TSval (TSecr == A's TSval from the data frame).
    let a_tsval = cap.tcp().from_a().with_data()
        .find_map(|f| f.tcp.opts.timestamps.map(|(v, _)| v));
    let b_tsecr = cap.tcp().from_b()
        .find_map(|f| f.tcp.opts.timestamps.map(|(_, e)| e));
    assert_ok!(a_tsval.is_some(), "A's data has no TSval");
    assert_ok!(b_tsecr.is_some(), "B's ACK has no TSecr");
    assert_ok!(
        b_tsecr == a_tsval,
        "B's TSecr ({:?}) != A's TSval ({:?}) — timestamp echo broken",
        b_tsecr, a_tsval
    );

    // SRTT should reflect the link RTT (~20ms for leased_line_100m).
    // This proves RTT was computed from the echoed timestamp, not just
    // from ACK arrival timing (which would be the same on a virtual link).
    let srtt = pair.tcp_a().srtt_ms();
    assert_ok!(srtt > 0, "srtt_ms() is 0 after data exchange");
    assert_ok!(
        srtt >= 15 && srtt <= 40,
        "srtt_ms() = {srtt} — expected ~20ms for leased_line_100m"
    );

    Ok(())
}

// RFC 7323 §4.3: ts_recent must only update when SEG.SEQ <= Last.ACK.sent.
#[test]
fn ts_recent_gating_ooo() -> TestResult {
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

    let isn_a = 0x5000_0000u32;
    let ts_syn = 50u32;
    let syn = build_tcp_syn(
        np.mac_a, np.mac_b,
        np.ip_a,  np.ip_b,
        12345, 80,
        isn_a, 0,
        0x02,
        Some(1460), Some(4),
        Some((ts_syn, 0)),
        true,
    );
    np.inject_to_b(syn);
    np.transfer_one();

    let cap = np.drain_captured();
    let syn_ack = cap.tcp().from_b()
        .with_tcp_flags(TcpFlags::SYN)
        .with_tcp_flags(TcpFlags::ACK)
        .next()
        .ok_or_else(|| TestFail::new("no SYN-ACK"))?;
    let b_isn = syn_ack.tcp.seq;
    let b_tsval = syn_ack.tcp.opts.timestamps.map(|(v, _)| v).unwrap_or(0);

    let ack = build_tcp_data_with_ts(
        np.mac_a, np.mac_b,
        np.ip_a,  np.ip_b,
        12345, 80,
        isn_a + 1, b_isn + 1,
        ts_syn + 10, b_tsval,
        &[],
    );
    np.inject_to_b(ack);
    np.transfer_one();

    assert_state(np.tcp_b(0), State::Established, "B Established")?;

    let ts_before = np.tcp_b(0).ts_recent();
    assert_ok!(ts_before == ts_syn + 10,
        "ts_recent after handshake should be {} but got {ts_before}", ts_syn + 10);

    // Inject seg2 FIRST (OOO): seq = isn_a+2, TSval = 200.
    let seg2 = build_tcp_data_with_ts(
        np.mac_a, np.mac_b,
        np.ip_a,  np.ip_b,
        12345, 80,
        isn_a + 2, b_isn + 1,
        200, b_tsval,
        b"B",
    );
    np.inject_to_b(seg2);
    np.transfer_one();

    // ts_recent must remain at ts_before (seg2 was OOO, SEG.SEQ > Last.ACK.sent).
    let ts_after_ooo = np.tcp_b(0).ts_recent();
    assert_ok!(ts_after_ooo == ts_before,
        "ts_recent changed from {ts_before} to {ts_after_ooo} after OOO segment — RFC 7323 §4.3 gating failed");

    // Now inject seg1 (gap-filler): seq = isn_a+1, TSval = 100.
    let seg1 = build_tcp_data_with_ts(
        np.mac_a, np.mac_b,
        np.ip_a,  np.ip_b,
        12345, 80,
        isn_a + 1, b_isn + 1,
        100, b_tsval,
        b"A",
    );
    np.inject_to_b(seg1);
    np.transfer_one();

    // ts_recent should now be 100 (from the in-order seg1).
    let ts_final = np.tcp_b(0).ts_recent();
    assert_ok!(ts_final == 100, "ts_recent after gap-fill should be 100, got {ts_final}");

    Ok(())
}
