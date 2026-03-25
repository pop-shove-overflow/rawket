#![allow(dead_code, unused_imports)]
use rawket::tcp::{State, TcpConfig, TcpError, TcpFlags, TcpSocket};
use rawket::bridge::{Impairment, PacketSpec};
use rawket::filter;
use std::net::Ipv4Addr;
use crate::{
    TestResult, assert_ok,
    assert::{assert_ack, assert_error_fired, assert_flags, assert_flags_exact, assert_state},
    capture::{Dir, ParsedFrameExt},
    harness::{setup_network_pair, setup_tcp_pair},
    packet::{build_tcp_data, build_tcp_data_with_flags, build_tcp_data_with_ts,
             build_tcp_rst, build_tcp_syn, build_udp_data},
};

// RFC 9293 §3.5 (Connection Establishment): Three-way handshake SYN, SYN-ACK, ACK.
#[test]
fn basic_handshake() -> TestResult {
    use rawket::bridge::LinkProfile;
    let (pair, cap) = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect_and_capture();

    let all_frames: Vec<_> = cap.all_tcp().collect();

    // Initial SYN: SYN set, ACK not set.
    let syn_frames: Vec<_> = all_frames.iter()
        .filter(|f| f.tcp.flags.has(TcpFlags::SYN) && !f.tcp.flags.has(TcpFlags::ACK))
        .collect();
    assert_ok!(syn_frames.len() == 1, "expected exactly 1 SYN, got {} (total frames: {})", syn_frames.len(), all_frames.len());

    // SYN-ACK: both SYN and ACK set.
    let synack_frames: Vec<_> = all_frames.iter()
        .filter(|f| f.tcp.flags.has(TcpFlags::SYN) && f.tcp.flags.has(TcpFlags::ACK))
        .collect();
    assert_ok!(synack_frames.len() == 1, "expected exactly 1 SYN-ACK, got {}", synack_frames.len());

    // Final ACK: ACK set, SYN not set.
    let ack_frames: Vec<_> = all_frames.iter()
        .filter(|f| f.tcp.flags.has(TcpFlags::ACK) && !f.tcp.flags.has(TcpFlags::SYN))
        .collect();
    assert_ok!(!ack_frames.is_empty(), "no ACK frame captured");

    let syn    = syn_frames[0];
    let synack = synack_frames[0];
    let ack    = ack_frames[0];

    // Exact flag verification: SYN carries ECE|CWR for ECN negotiation (RFC 3168 §6.1.1).
    assert_flags_exact(syn, TcpFlags::SYN | TcpFlags::ECE | TcpFlags::CWR, "SYN flags")?;
    // SYN-ACK echoes ECE to confirm ECN support (RFC 3168 §6.1.1).
    assert_flags_exact(synack, TcpFlags::SYN | TcpFlags::ACK | TcpFlags::ECE, "SYN-ACK flags")?;
    assert_flags_exact(ack, TcpFlags::ACK, "final ACK flags")?;

    assert_ack(synack, syn.tcp.seq.wrapping_add(1), "SYN-ACK acks client ISN")?;
    assert_ack(ack,    synack.tcp.seq.wrapping_add(1), "ACK acks server ISN")?;

    // Direction: SYN from A, SYN-ACK from B, ACK from A.
    assert_ok!(syn.dir == Dir::AtoB, "SYN should be from A, got {:?}", syn.dir);
    assert_ok!(synack.dir == Dir::BtoA, "SYN-ACK should be from B, got {:?}", synack.dir);
    assert_ok!(ack.dir == Dir::AtoB, "third ACK should be from A, got {:?}", ack.dir);

    // SYN and SYN-ACK must carry no payload.
    assert_ok!(syn.payload_len == 0, "SYN has payload ({} bytes)", syn.payload_len);
    assert_ok!(synack.payload_len == 0, "SYN-ACK has payload ({} bytes)", synack.payload_len);

    // SYN must carry MSS option (RFC 9293 §3.7.1).
    assert_ok!(
        syn.tcp.opts.mss.is_some(),
        "SYN missing MSS option"
    );
    assert_ok!(
        synack.tcp.opts.mss.is_some(),
        "SYN-ACK missing MSS option"
    );

    // Both SYN and SYN-ACK must advertise a non-zero window.
    assert_ok!(syn.tcp.window_raw > 0, "SYN window is 0");
    assert_ok!(synack.tcp.window_raw > 0, "SYN-ACK window is 0");

    assert_state(pair.tcp_a(), State::Established, "client")?;
    assert_state(pair.tcp_b(), State::Established, "server")?;

    Ok(())
}

// RFC 9293 §3.5 (Connection Establishment): Simultaneous open — both SYNs
// cross in flight, both sides reach SynReceived then Established.
#[test]
fn simultaneous_open() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut np = setup_network_pair()
        .profile(LinkProfile::leased_line_100m());
    let cfg = TcpConfig::default();

    let client = TcpSocket::connect_now(
        np.iface_a(),
        "10.0.0.1:12345".parse().unwrap(),
        "10.0.0.2:80".parse().unwrap(),
        Ipv4Addr::from([10, 0, 0, 2]),
        |_| {}, |_| {}, cfg.clone(),
    )?;
    let ia = np.add_tcp_a(client);

    let peer = TcpSocket::connect_now(
        np.iface_b(),
        "10.0.0.2:80".parse().unwrap(),
        "10.0.0.1:12345".parse().unwrap(),
        Ipv4Addr::from([10, 0, 0, 1]),
        |_| {}, |_| {}, cfg,
    )?;
    let ib = np.add_tcp_b(peer);

    // Both SYNs cross in flight → SynReceived → SYN-ACK exchange → Established.
    // Step through to verify SynReceived intermediate state (RFC 9293 §3.5 Fig 8).
    // Advance past link delay so SYNs arrive, then poll once.
    let mut saw_syn_rcvd = false;
    np.transfer_while(|p| {
        if p.tcp_a(ia).state == State::SynReceived
            && p.tcp_b(ib).state == State::SynReceived
        {
            saw_syn_rcvd = true;
            return false;
        }
        true
    });
    assert_ok!(saw_syn_rcvd, "never observed both sides in SynReceived");

    // Complete the handshake.
    np.transfer();

    assert_state(np.tcp_a(ia), State::Established, "A")?;
    assert_state(np.tcp_b(ib), State::Established, "B")?;

    // Verify the simultaneous open handshake from captures:
    // 2 SYNs (one from each side) + 2 SYN-ACKs + 0 RSTs.
    let cap = np.drain_captured();

    let syn_count = cap.all_tcp()
        .filter(|f| f.tcp.flags.has(TcpFlags::SYN) && !f.tcp.flags.has(TcpFlags::ACK))
        .count();
    assert_ok!(syn_count == 2, "expected 2 SYNs, got {syn_count}");

    let synack_count = cap.all_tcp()
        .filter(|f| f.tcp.flags.has(TcpFlags::SYN) && f.tcp.flags.has(TcpFlags::ACK))
        .count();
    assert_ok!(synack_count == 2, "expected 2 SYN-ACKs, got {synack_count}");

    let rst_count = cap.all_tcp()
        .filter(|f| f.tcp.flags.has(TcpFlags::RST))
        .count();
    assert_ok!(rst_count == 0, "simultaneous open produced {rst_count} RST frame(s)");

    // Verify SYN-ACK sequence numbers match the simultaneous open path.
    let a_syn = cap.all_tcp().find(|f| f.dir == Dir::AtoB && f.tcp.flags.has(TcpFlags::SYN) && !f.tcp.flags.has(TcpFlags::ACK))
        .ok_or_else(|| crate::assert::TestFail::new("no AtoB SYN"))?;
    let b_syn = cap.all_tcp().find(|f| f.dir == Dir::BtoA && f.tcp.flags.has(TcpFlags::SYN) && !f.tcp.flags.has(TcpFlags::ACK))
        .ok_or_else(|| crate::assert::TestFail::new("no BtoA SYN"))?;
    let b_synack = cap.all_tcp().find(|f| f.dir == Dir::BtoA && f.tcp.flags.has(TcpFlags::SYN) && f.tcp.flags.has(TcpFlags::ACK))
        .ok_or_else(|| crate::assert::TestFail::new("no BtoA SYN-ACK"))?;
    let a_synack = cap.all_tcp().find(|f| f.dir == Dir::AtoB && f.tcp.flags.has(TcpFlags::SYN) && f.tcp.flags.has(TcpFlags::ACK))
        .ok_or_else(|| crate::assert::TestFail::new("no AtoB SYN-ACK"))?;

    assert_ack(&b_synack, a_syn.tcp.seq.wrapping_add(1), "B's SYN-ACK acks A's ISN")?;
    assert_ack(&a_synack, b_syn.tcp.seq.wrapping_add(1), "A's SYN-ACK acks B's ISN")?;

    // Data flow must work after simultaneous open.
    np.clear_capture();
    np.tcp_a_mut(ia).send(b"from-a")?;
    np.tcp_b_mut(ib).send(b"from-b")?;
    let result = np.transfer();

    assert_state(np.tcp_a(ia), State::Established, "A after data")?;
    assert_state(np.tcp_b(ib), State::Established, "B after data")?;

    let cap = np.drain_captured();
    let a_data = cap.tcp().filter(|f| f.dir == Dir::AtoB && f.payload_len > 0).count();
    let b_data = cap.tcp().filter(|f| f.dir == Dir::BtoA && f.payload_len > 0).count();
    assert_ok!(a_data > 0, "no data segments from A to B after simultaneous open");
    assert_ok!(b_data > 0, "no data segments from B to A after simultaneous open");

    // Verify app-level delivery: B received "from-a", A received "from-b".
    let b_received = result.b.get(&ib).map(|v| v.as_slice()).unwrap_or(&[]);
    let a_received = result.a.get(&ia).map(|v| v.as_slice()).unwrap_or(&[]);
    assert_ok!(b_received == b"from-a", "B did not receive 'from-a': got {:?}", b_received);
    assert_ok!(a_received == b"from-b", "A did not receive 'from-b': got {:?}", a_received);

    Ok(())
}

// RFC 9293 §3.5.3 (Reset Processing): RST in Established aborts the connection.
#[test]
fn rst_in_established() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    pair.tcp_b_mut().abort()?;
    pair.transfer();

    assert_state(pair.tcp_a(), State::Closed, "A Closed after RST from B")?;
    assert_state(pair.tcp_b(), State::Closed, "B Closed after abort()")?;
    assert_error_fired(pair.tcp_a(), TcpError::Reset, "A error after RST")?;

    let cap = pair.drain_captured();
    let rst_count = cap.tcp()
        .direction(Dir::BtoA)
        .with_tcp_flags(TcpFlags::RST)
        .count();
    assert_ok!(rst_count == 1, "expected 1 RST from B, got {rst_count}");

    Ok(())
}

// RFC 5961 §3.2 (RST Robustness): Out-of-window RST must be silently dropped.
#[test]
fn rst_with_invalid_seq() -> TestResult {
    use rawket::bridge::LinkProfile;
    let (mut pair, cap) = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect_and_capture();

    let synack = cap.all_tcp()
        .find(|f| f.tcp.flags.has(TcpFlags::SYN) && f.tcp.flags.has(TcpFlags::ACK))
        .ok_or_else(|| crate::assert::TestFail::new("no SYN-ACK in capture"))?;

    let rcv_nxt = synack.tcp.seq.wrapping_add(1);
    let wscale = synack.tcp.opts.window_scale.unwrap_or(0);
    let rcv_wnd_scaled = (synack.tcp.window_raw as u32) << wscale;
    let invalid_seq = rcv_nxt.wrapping_add(16 << 20);
    let offset = invalid_seq.wrapping_sub(rcv_nxt);
    assert_ok!(
        offset > rcv_wnd_scaled,
        "invalid_seq offset {offset} is within receive window {rcv_wnd_scaled} — test scenario invalid"
    );

    let rst = build_tcp_rst(
        pair.mac_b, pair.mac_a,
        pair.ip_b,  pair.ip_a,
        80, 12345,
        invalid_seq,
    );
    pair.clear_capture();
    pair.inject_to_a(rst);
    pair.transfer();

    assert_state(pair.tcp_a(), State::Established, "client")?;
    assert_ok!(
        pair.tcp_a().last_error.is_none(),
        "out-of-window RST should not set error, got {:?}", pair.tcp_a().last_error
    );

    let cap = pair.drain_captured();
    let a_sent = cap.tcp().direction(Dir::AtoB).count();
    assert_ok!(a_sent == 0, "A sent {a_sent} frame(s) in response to out-of-window RST — expected 0");

    Ok(())
}

// RFC 9293 §3.8.1 (Retransmission): SYN retransmit with exponential backoff
// until max_retransmits is exhausted.
#[test]
fn syn_retransmit() -> TestResult {
    use rawket::bridge::LinkProfile;
    let max_retransmits: u8 = 4;
    let rto_min_ms: u64 = 10;
    let mut np = setup_network_pair()
        .profile(LinkProfile::leased_line_100m());
    let cfg = TcpConfig::default().rto_min_ms(rto_min_ms).max_retransmits(max_retransmits);

    np.add_impairment_to_b(Impairment::Drop(PacketSpec::matching(filter::tcp::syn())));

    let client = TcpSocket::connect_now(
        np.iface_a(),
        "10.0.0.1:12345".parse().unwrap(),
        "10.0.0.2:80".parse().unwrap(),
        Ipv4Addr::from([10, 0, 0, 2]),
        |_| {}, |_| {}, cfg,
    )?;
    let ia = np.add_tcp_a(client);

    np.transfer_while(|p| p.tcp_a(ia).state != State::Closed);

    assert_state(np.tcp_a(ia), State::Closed, "client after SYN exhaustion")?;
    assert_error_fired(np.tcp_a(ia), TcpError::Timeout, "client error after SYN exhaustion")?;

    // Verify exact SYN count: 1 initial + max_retransmits retries.
    let cap = np.drain_captured();
    let syns: Vec<_> = cap.all_tcp()
        .filter(|f| f.dir == Dir::AtoB
            && f.tcp.flags.has(TcpFlags::SYN)
            && !f.tcp.flags.has(TcpFlags::ACK))
        .collect();
    // 1 initial SYN + max_retransmits retransmits.
    let expected_syns = (max_retransmits as usize) + 1;
    assert_ok!(
        syns.len() == expected_syns,
        "expected {expected_syns} SYNs (1 initial + {max_retransmits} retransmits), got {}",
        syns.len()
    );

    // Verify exponential backoff: each interval should be ~2× the previous.
    // Intervals: rto_min, 2*rto_min, 4*rto_min, 8*rto_min, ...
    // Only check the first max_retransmits intervals (the last retransmit
    // may share a timestamp with the close).
    let check_count = (syns.len() - 1).min(max_retransmits as usize);
    for i in 1..=check_count {
        let interval_ns = syns[i].ts_ns.saturating_sub(syns[i - 1].ts_ns);
        let interval_ms = interval_ns / 1_000_000;
        let expected_ms = rto_min_ms << (i - 1);
        // Allow 50% tolerance for timing granularity.
        assert_ok!(
            interval_ms >= expected_ms / 2 && interval_ms <= expected_ms * 2,
            "SYN retransmit {i}: interval {interval_ms}ms, expected ~{expected_ms}ms (2^{} * {rto_min_ms}ms)",
            i - 1
        );
    }

    Ok(())
}

// RFC 9293 §3.5.3 (Reset Processing): RST+ACK in SynSent with valid ack
// closes the connection.
#[test]
fn rst_in_syn_sent() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut np = setup_network_pair()
        .profile(LinkProfile::leased_line_100m());
    let cfg = TcpConfig::default();

    // Drop everything so B never sees the SYN (A stays in SynSent).
    np.add_impairment_to_a(Impairment::Drop(PacketSpec::any()));

    let client = TcpSocket::connect_now(
        np.iface_a(),
        "10.0.0.1:12345".parse().unwrap(),
        "10.0.0.2:80".parse().unwrap(),
        Ipv4Addr::from([10, 0, 0, 2]),
        |_| {}, |_| {}, cfg,
    )?;
    let ia = np.add_tcp_a(client);

    // SYN was sent (by connect_now) but dropped — find its seq from captures.
    let a_isn = np.drain_captured().all_tcp()
        .find(|f| f.dir == Dir::AtoB && f.tcp.flags.has(TcpFlags::SYN))
        .map(|f| f.tcp.seq)
        .ok_or_else(|| crate::assert::TestFail::new("no SYN from A"))?;

    np.clear_impairments();

    let rst = build_tcp_data_with_flags(
        np.mac_b, np.mac_a,
        np.ip_b,  np.ip_a,
        80, 12345,
        0,
        a_isn + 1,
        0x14, // RST|ACK
        0,
        &[],
    );
    np.inject_to_a(rst);
    np.transfer();

    assert_state(np.tcp_a(ia), State::Closed, "A Closed after RST in SynSent")?;
    assert_error_fired(np.tcp_a(ia), TcpError::Reset, "A error = Reset")?;

    Ok(())
}

// RFC 5961 §4.2 (SYN Robustness): In-window SYN in Established must trigger
// a challenge ACK (not reset the connection).
#[test]
fn in_window_syn_challenge_ack() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    pair.tcp_a_mut().send(b"x")?;
    pair.transfer();

    let cap = pair.drain_captured();
    let (b_snd_nxt, a_snd_nxt) = {
        let af = cap.tcp()
            .find(|f| f.dir == Dir::AtoB && f.payload_len > 0)
            .ok_or_else(|| crate::assert::TestFail::new("no AtoB data frame"))?;
        (af.tcp.ack, af.tcp.seq + af.payload_len as u32)
    };

    let syn = build_tcp_syn(
        pair.mac_b, pair.mac_a,
        pair.ip_b,  pair.ip_a,
        80, 12345,
        b_snd_nxt,
        a_snd_nxt,
        0x02,
        Some(1460), None, None, false,
    );
    pair.clear_capture();
    pair.inject_to_a(syn);
    pair.transfer();

    assert_state(pair.tcp_a(), State::Established, "A must stay Established after in-window SYN")?;

    let cap2 = pair.drain_captured();
    let is_pure_ack = |f: &crate::capture::ParsedFrame| {
        f.dir == Dir::AtoB
            && f.tcp.flags.has(TcpFlags::ACK)
            && !f.tcp.flags.has(TcpFlags::SYN)
            && !f.tcp.flags.has(TcpFlags::RST)
            && !f.tcp.flags.has(TcpFlags::FIN)
            && f.payload_len == 0
    };
    let challenge = cap2.tcp().find(|f| is_pure_ack(f))
        .ok_or_else(|| crate::assert::TestFail::new(
            "A did not send challenge ACK for in-window SYN"
        ))?;

    // RFC 9293 §3.10.7.4: challenge ACK carries SEQ=SND.NXT, ACK=RCV.NXT.
    assert_ok!(
        challenge.tcp.seq == a_snd_nxt,
        "challenge ACK SEQ ({}) != SND.NXT ({a_snd_nxt})",
        challenge.tcp.seq
    );
    assert_ok!(
        challenge.tcp.ack == b_snd_nxt,
        "challenge ACK ACK ({}) != RCV.NXT ({b_snd_nxt})",
        challenge.tcp.ack
    );

    // Exactly 1 challenge ACK expected.
    let ack_count = cap2.tcp().filter(|f| is_pure_ack(f)).count();
    assert_ok!(ack_count == 1, "expected exactly 1 challenge ACK, got {ack_count}");

    Ok(())
}

// RFC 5961 §3.2 (RST Robustness): RST with SEQ == RCV.NXT (exact match)
// must immediately reset the connection.
#[test]
fn rst_exact_match_resets() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    pair.tcp_a_mut().send(b"x")?;
    pair.transfer();

    let b_snd_nxt = pair.drain_captured().tcp()
        .find(|f| f.dir == Dir::AtoB && f.payload_len > 0)
        .map(|f| f.tcp.ack)
        .ok_or_else(|| crate::assert::TestFail::new("no AtoB data frame"))?;

    let rst = build_tcp_rst(
        pair.mac_b, pair.mac_a,
        pair.ip_b,  pair.ip_a,
        80, 12345,
        b_snd_nxt,
    );
    pair.clear_capture();
    pair.inject_to_a(rst);
    pair.transfer();

    assert_state(pair.tcp_a(), State::Closed, "A Closed after exact RST")?;
    assert_error_fired(pair.tcp_a(), TcpError::Reset, "A error = Reset")?;

    // A must not send any response to an exact-match RST.
    let cap = pair.drain_captured();
    let a_sent = cap.tcp().direction(Dir::AtoB).count();
    assert_ok!(a_sent == 0, "A sent {a_sent} frame(s) in response to exact RST — expected 0");

    Ok(())
}

// RFC 5961 §3.2 (RST Robustness): In-window RST with SEQ != RCV.NXT must
// trigger a challenge ACK instead of resetting the connection.
#[test]
fn rst_in_window_challenge_ack() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    pair.tcp_a_mut().send(b"x")?;
    pair.transfer();

    let a_snd_nxt = pair.tcp_a().snd_nxt();

    let b_snd_nxt = pair.drain_captured().tcp()
        .find(|f| f.dir == Dir::AtoB && f.payload_len > 0)
        .map(|f| f.tcp.ack)
        .ok_or_else(|| crate::assert::TestFail::new("no AtoB data frame"))?;

    // RST with SEQ just past the exact match — in-window but not exact.
    let rst = build_tcp_rst(
        pair.mac_b, pair.mac_a,
        pair.ip_b,  pair.ip_a,
        80, 12345,
        b_snd_nxt + 1,
    );
    pair.clear_capture();
    pair.inject_to_a(rst);
    pair.transfer();

    assert_state(pair.tcp_a(), State::Established, "A must stay Established after in-window-but-not-exact RST")?;

    let cap = pair.drain_captured();
    // Filter for pure ACK: has ACK but not SYN/RST/FIN.
    let challenge = cap.tcp()
        .find(|f| f.dir == Dir::AtoB
            && f.tcp.flags.has(TcpFlags::ACK)
            && !f.tcp.flags.has(TcpFlags::SYN)
            && !f.tcp.flags.has(TcpFlags::RST)
            && !f.tcp.flags.has(TcpFlags::FIN)
            && f.payload_len == 0);
    assert_ok!(challenge.is_some(), "A did not send challenge ACK for in-window RST");
    let challenge = challenge.unwrap();

    // RFC 9293 §3.10.7.4: challenge ACK carries SEQ=SND.NXT, ACK=RCV.NXT.
    assert_ok!(
        challenge.tcp.seq == a_snd_nxt,
        "challenge ACK SEQ={} != SND.NXT={a_snd_nxt}",
        challenge.tcp.seq
    );
    assert_ok!(
        challenge.tcp.ack == b_snd_nxt,
        "challenge ACK ACK={} != RCV.NXT={b_snd_nxt}",
        challenge.tcp.ack
    );

    // Exactly 1 challenge ACK expected.
    let ack_count = cap.tcp()
        .filter(|f| f.dir == Dir::AtoB
            && f.tcp.flags.has(TcpFlags::ACK)
            && !f.tcp.flags.has(TcpFlags::SYN)
            && !f.tcp.flags.has(TcpFlags::RST)
            && !f.tcp.flags.has(TcpFlags::FIN)
            && f.payload_len == 0)
        .count();
    assert_ok!(ack_count == 1, "expected exactly 1 challenge ACK, got {ack_count}");

    // Test deeper in-window RST — midway through receive window.
    pair.clear_capture();
    let rst_deep = build_tcp_rst(
        pair.mac_b, pair.mac_a,
        pair.ip_b,  pair.ip_a,
        80, 12345,
        b_snd_nxt.wrapping_add(1000),
    );
    pair.clear_capture();
    pair.inject_to_a(rst_deep);
    pair.transfer();

    assert_state(pair.tcp_a(), State::Established, "A must stay Established after deeper in-window RST")?;

    let cap2 = pair.drain_captured();
    let deep_challenge = cap2.tcp()
        .find(|f| f.dir == Dir::AtoB
            && f.tcp.flags.has(TcpFlags::ACK)
            && !f.tcp.flags.has(TcpFlags::SYN)
            && !f.tcp.flags.has(TcpFlags::RST)
            && !f.tcp.flags.has(TcpFlags::FIN)
            && f.payload_len == 0);
    assert_ok!(deep_challenge.is_some(), "A did not send challenge ACK for deeper in-window RST");
    let deep_challenge = deep_challenge.unwrap();
    assert_ok!(
        deep_challenge.tcp.seq == a_snd_nxt,
        "deep challenge ACK SEQ={} != SND.NXT={a_snd_nxt}",
        deep_challenge.tcp.seq
    );
    assert_ok!(
        deep_challenge.tcp.ack == b_snd_nxt,
        "deep challenge ACK ACK={} != RCV.NXT={b_snd_nxt}",
        deep_challenge.tcp.ack
    );

    Ok(())
}

// RFC 5961 §5, §7 (Challenge ACK Rate Limiting): Challenge ACKs must be
// rate-limited to prevent amplification attacks.
#[test]
fn challenge_ack_rate_limit() -> TestResult {
    use rawket::bridge::LinkProfile;
    let limit = rawket::tcp::CHALLENGE_ACK_LIMIT as usize;
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    pair.tcp_a_mut().send(b"x")?;
    pair.transfer();

    let b_snd_nxt = pair.drain_captured().tcp()
        .find(|f| f.dir == Dir::AtoB && f.payload_len > 0)
        .map(|f| f.tcp.ack)
        .ok_or_else(|| crate::assert::TestFail::new("no AtoB data frame"))?;

    let inject_rst = |pair: &mut crate::harness::TcpSocketPair| {
        let rst = build_tcp_rst(
            pair.mac_b, pair.mac_a,
            pair.ip_b,  pair.ip_a,
            80, 12345,
            b_snd_nxt + 1,
        );
        pair.inject_to_a(rst);
    };

    pair.clear_capture();
    for _ in 0..limit * 2 {
        inject_rst(&mut pair);
    }
    pair.transfer();

    let is_pure_ack = |f: &crate::capture::ParsedFrame| {
        f.dir == Dir::AtoB
            && f.tcp.flags.has(TcpFlags::ACK)
            && !f.tcp.flags.has(TcpFlags::SYN)
            && !f.tcp.flags.has(TcpFlags::RST)
            && !f.tcp.flags.has(TcpFlags::FIN)
            && f.payload_len == 0
    };

    let cap = pair.drain_captured();
    let ack_count = cap.tcp().filter(|f| is_pure_ack(f)).count();

    assert_ok!(ack_count > 0, "no challenge ACKs sent");
    assert_ok!(
        ack_count == limit,
        "expected exactly {limit} challenge ACKs (rate limit), got {ack_count}"
    );
    assert_state(pair.tcp_a(), State::Established, "A must survive burst of in-window RSTs")?;

    // Recovery: advance clock past the 1s window, then verify challenge ACKs resume.
    pair.advance_both(1001);
    pair.clear_capture();

    inject_rst(&mut pair);
    pair.transfer();

    let cap2 = pair.drain_captured();
    let recovery_acks = cap2.tcp().filter(|f| is_pure_ack(f)).count();
    assert_ok!(
        recovery_acks == 1,
        "expected 1 challenge ACK after rate-limit window reset, got {recovery_acks}"
    );

    Ok(())
}

// RFC 9293 §3.10.7.4 (Out-of-Window Segments): Data with SEQ outside the
// receive window must be dropped; an ACK with ACK=RCV.NXT is sent.
#[test]
fn oow_data_segment_dropped() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    pair.tcp_a_mut().send(b"x")?;
    pair.transfer();

    let cap = pair.drain_captured();
    let (b_rcv_nxt, b_snd_nxt) = {
        let af = cap.tcp()
            .find(|f| f.dir == Dir::AtoB && f.payload_len > 0)
            .ok_or_else(|| crate::assert::TestFail::new("no AtoB data"))?;
        (af.tcp.seq + af.payload_len as u32, af.tcp.ack)
    };

    let oow = build_tcp_data(
        pair.mac_a, pair.mac_b,
        pair.ip_a,  pair.ip_b,
        12345, 80,
        b_rcv_nxt.wrapping_add(2_000_000),
        b_snd_nxt,
        b"out-of-window",
    );
    pair.clear_capture();
    pair.inject_to_b(oow);
    pair.transfer();

    let cap2 = pair.drain_captured();
    let ack_advanced = cap2.tcp()
        .filter(|f| f.dir == Dir::BtoA && f.tcp.flags.has(TcpFlags::ACK))
        .any(|f| f.tcp.ack > b_rcv_nxt);
    assert_ok!(!ack_advanced, "B advanced ACK for out-of-window segment");

    assert_state(pair.tcp_b(), State::Established, "B must stay Established")?;

    // RFC 9293 §3.10.7.4: B must respond with an ACK carrying ACK=RCV.NXT.
    let resp = cap2.tcp()
        .find(|f| f.dir == Dir::BtoA && f.tcp.flags.has(TcpFlags::ACK));
    assert_ok!(resp.is_some(), "B did not send ACK for out-of-window segment");
    let resp = resp.unwrap();
    assert_ok!(
        resp.tcp.ack == b_rcv_nxt,
        "response ACK={} != RCV.NXT={b_rcv_nxt}",
        resp.tcp.ack
    );

    // Test below-RCV.NXT: segment with seq before the receive window.
    pair.clear_capture();
    let below = build_tcp_data(
        pair.mac_a, pair.mac_b,
        pair.ip_a,  pair.ip_b,
        12345, 80,
        b_rcv_nxt.wrapping_sub(100),
        b_snd_nxt,
        b"below-window",
    );
    pair.inject_to_b(below);
    pair.transfer();

    assert_state(pair.tcp_b(), State::Established, "B must stay Established after below-window segment")?;

    let cap3 = pair.drain_captured();
    let resp2 = cap3.tcp()
        .find(|f| f.dir == Dir::BtoA && f.tcp.flags.has(TcpFlags::ACK));
    assert_ok!(resp2.is_some(), "B did not send ACK for below-window segment");
    let resp2 = resp2.unwrap();
    assert_ok!(
        resp2.tcp.ack == b_rcv_nxt,
        "below-window response ACK={} != RCV.NXT={b_rcv_nxt}",
        resp2.tcp.ack
    );

    Ok(())
}

// RFC 9293 §3.10.2 (SEND Call): In SYN-SENT and SYN-RECEIVED, data is
// queued for transmission after entering ESTABLISHED.  send() must succeed
// (return Ok), and the queued data must be delivered once the handshake
// completes.
#[test]
fn send_in_non_established() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut np = setup_network_pair()
        .profile(LinkProfile::leased_line_100m());
    let cfg = TcpConfig::default();

    // Drop B→A so the handshake doesn't complete — A stays in SynSent.
    np.add_impairment_to_a(Impairment::Drop(PacketSpec::any()));

    let client = TcpSocket::connect_now(
        np.iface_a(),
        "10.0.0.1:12345".parse().unwrap(),
        "10.0.0.2:80".parse().unwrap(),
        Ipv4Addr::from([10, 0, 0, 2]),
        |_| {}, |_| {}, cfg.clone(),
    )?;
    let ia = np.add_tcp_a(client);

    assert_state(np.tcp_a(ia), State::SynSent, "A should be SynSent")?;

    // RFC 9293 §3.10.2: SEND in SYN-SENT must queue data, not return error.
    np.tcp_a_mut(ia).send(b"queued-in-syn-sent")?;

    assert_ok!(
        np.tcp_a(ia).send_buf_len() == 18,
        "data not queued in SYN-SENT: send_buf_len={}", np.tcp_a(ia).send_buf_len()
    );

    // Complete the handshake — add server, clear impairments, transfer.
    let server = TcpSocket::accept(
        np.iface_b(),
        "10.0.0.2:80".parse().unwrap(),
        |_| {}, |_| {}, cfg,
    )?;
    np.add_tcp_b(server);
    np.clear_impairments();
    np.transfer();

    assert_state(np.tcp_a(ia), State::Established, "A should be Established")?;

    // Queued data must have been transmitted after handshake.
    let cap = np.drain_captured();
    let total: usize = cap.tcp().from_a().with_data().map(|f| f.payload_len).sum();
    assert_ok!(
        total == 18,
        "queued data not transmitted after handshake: {total} bytes sent, expected 18"
    );

    // Verify queued data was transmitted (send_buf drained after handshake).
    assert_ok!(
        np.tcp_a(ia).send_buf_len() == 0,
        "send_buf not drained after handshake: {}", np.tcp_a(ia).send_buf_len()
    );

    Ok(())
}

// RFC 9293 §3.5.3 (Reset Processing): In SynSent, a bare RST (no ACK) and a
// RST+ACK with invalid ack must both be silently dropped.
#[test]
fn rst_bare_in_syn_sent_dropped() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut np = setup_network_pair()
        .profile(LinkProfile::leased_line_100m());
    let cfg = TcpConfig::default();

    np.add_impairment_to_a(Impairment::Drop(PacketSpec::any()));

    let client = TcpSocket::connect_now(
        np.iface_a(),
        "10.0.0.1:12345".parse().unwrap(),
        "10.0.0.2:80".parse().unwrap(),
        Ipv4Addr::from([10, 0, 0, 2]),
        |_| {}, |_| {}, cfg,
    )?;
    let ia = np.add_tcp_a(client);

    assert_state(np.tcp_a(ia), State::SynSent, "A in SynSent")?;

    np.clear_impairments();

    // Capture A's ISN from the (dropped) SYN before clearing capture.
    let a_isn = np.drain_captured().all_tcp()
        .find(|f| f.dir == Dir::AtoB && f.tcp.flags.has(TcpFlags::SYN))
        .map(|f| f.tcp.seq)
        .ok_or_else(|| crate::assert::TestFail::new("no SYN from A"))?;

    // Test 1: bare RST (no ACK) — must be silently dropped.
    let bare_rst = build_tcp_data_with_flags(
        np.mac_b, np.mac_a,
        np.ip_b,  np.ip_a,
        80, 12345,
        0, 0,
        0x04, // RST only
        0,
        &[],
    );
    np.clear_capture();
    np.inject_to_a(bare_rst);
    np.transfer_one();

    assert_state(np.tcp_a(ia), State::SynSent, "A should stay SynSent after bare RST")?;
    assert_ok!(np.tcp_a(ia).last_error.is_none(), "bare RST should not set error");

    let cap = np.drain_captured();
    let a_sent = cap.tcp().filter(|f| f.dir == Dir::AtoB).count();
    assert_ok!(a_sent == 0, "A sent {a_sent} frame(s) in response to bare RST — expected 0");

    // Test 2: RST+ACK with wrong ack — must be silently dropped.
    np.clear_capture();
    let bad_ack_rst = build_tcp_data_with_flags(
        np.mac_b, np.mac_a,
        np.ip_b,  np.ip_a,
        80, 12345,
        0,
        a_isn + 999,
        0x14, // RST|ACK
        0,
        &[],
    );
    np.inject_to_a(bad_ack_rst);
    np.transfer_one();

    assert_state(np.tcp_a(ia), State::SynSent, "A should stay SynSent after RST+ACK with wrong ack")?;

    let cap2 = np.drain_captured();
    let a_sent2 = cap2.tcp().filter(|f| f.dir == Dir::AtoB).count();
    assert_ok!(a_sent2 == 0, "A sent {a_sent2} frame(s) in response to bad-ack RST — expected 0");

    Ok(())
}

// ── send_after_close ────────────────────────────────────────────────────────
//
// RFC 9293 §3.10.2: send() after close() must return error.
// After A calls close() (FinWait1), send() must fail with NotConnected.
#[test]
fn send_after_close() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    pair.tcp_a_mut().close()?;
    assert_ok!(
        pair.tcp_a().state == State::FinWait1,
        "A not in FinWait1 after close: {:?}", pair.tcp_a().state
    );

    let result = pair.tcp_a_mut().send(b"after-close");
    match result {
        Err(rawket::Error::NotConnected) => {}
        Err(e) => return Err(crate::assert::TestFail::new(
            format!("send() in FinWait1 returned wrong error: {e:?} (expected NotConnected)")
        )),
        Ok(()) => return Err(crate::assert::TestFail::new(
            "send() in FinWait1 should return NotConnected, got Ok"
        )),
    }

    // Progress to FinWait2.
    pair.transfer();
    assert_state(pair.tcp_a(), State::FinWait2, "A should reach FinWait2")?;
    let result2 = pair.tcp_a_mut().send(b"in-finwait2");
    assert_ok!(
        matches!(result2, Err(rawket::Error::NotConnected)),
        "send() in FinWait2 should return NotConnected, got {:?}", result2
    );

    // Progress to TimeWait.
    pair.tcp_b_mut().close()?;
    pair.transfer_while(|p| p.tcp_a(0).state != State::TimeWait);
    assert_state(pair.tcp_a(), State::TimeWait, "A should reach TimeWait")?;
    let result3 = pair.tcp_a_mut().send(b"in-timewait");
    assert_ok!(
        matches!(result3, Err(rawket::Error::NotConnected)),
        "send() in TimeWait should return NotConnected, got {:?}", result3
    );

    Ok(())
}

// ── send_in_close_wait ──────────────────────────────────────────────────────
//
// RFC 9293 §3.10.2: send() in CloseWait is allowed (half-open: peer closed,
// we can still send).
#[test]
fn send_in_close_wait() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    pair.tcp_b_mut().close()?;
    pair.transfer();
    assert_state(pair.tcp_a(), State::CloseWait, "A CloseWait")?;

    // send() should succeed in CloseWait.
    pair.clear_capture();
    let result = pair.tcp_a_mut().send(b"half-open-data");
    assert_ok!(result.is_ok(), "send() in CloseWait should succeed, got {:?}", result.err());

    let result = pair.transfer();
    let cap = pair.drain_captured();
    let data_from_a = cap.tcp().filter(|f| f.dir == Dir::AtoB && f.payload_len > 0).count();
    assert_ok!(data_from_a > 0, "no data segments from A in CloseWait — data never reached wire");

    // Verify B received the payload content.
    let received = result.b.get(&0).map(|v| v.as_slice()).unwrap_or(&[]);
    assert_ok!(
        received == b"half-open-data",
        "B did not receive expected payload: got {:?}", received
    );

    // close() after send completes the shutdown (CloseWait → LastAck → Closed).
    pair.tcp_a_mut().close()?;
    pair.transfer();
    assert_state(pair.tcp_a(), State::Closed, "A should reach Closed after close() in CloseWait")?;

    Ok(())
}

// ── unmatched_socket_rst ─────────────────────────────────────────────────────
//
// RFC 9293 §3.10.7: A TCP segment arriving at a port with no matching socket
// must elicit a RST.  For a SYN to a closed port: RST with SEQ=0, ACK=SEG.SEQ+1.
#[test]
fn unmatched_socket_rst() -> TestResult {
    use rawket::bridge::LinkProfile;
    // No TCP sockets — just two network stacks connected by a bridge.
    let mut np = setup_network_pair()
        .profile(LinkProfile::leased_line_100m());

    let isn: u32 = 1000;
    let syn = build_tcp_syn(
        np.mac_a, np.mac_b,
        np.ip_a,  np.ip_b,
        12345, 9999,   // port 9999 has no listener
        isn,
        0,
        0x02,          // SYN
        Some(1460), None, None, false,
    );
    np.inject_to_b(syn);
    // transfer_one, not transfer() — no sockets means transfer() never quiesces.
    np.transfer_one();

    let cap = np.drain_captured();
    let rst = cap.tcp().from_b()
        .with_tcp_flags(TcpFlags::RST)
        .next()
        .ok_or_else(|| crate::assert::TestFail::new("B did not send RST for unmatched SYN"))?;

    // RFC 9293 §3.10.7: RST for a SYN: SEQ=0, ACK=SEG.SEQ+SEG.LEN (ISN+1 for SYN).
    assert_ok!(
        rst.tcp.flags.has(TcpFlags::ACK),
        "RST for SYN must carry ACK flag"
    );
    assert_ok!(
        rst.tcp.seq == 0,
        "RST seq ({}) should be 0 for SYN-triggered RST", rst.tcp.seq
    );
    assert_ok!(
        rst.tcp.ack == isn + 1,
        "RST ack ({}) should be ISN+1 ({})", rst.tcp.ack, isn + 1
    );

    // Only one RST should be sent.
    let rst_count = cap.tcp().from_b()
        .with_tcp_flags(TcpFlags::RST)
        .count();
    assert_ok!(rst_count == 1, "expected 1 RST, got {rst_count}");

    Ok(())
}

// ── listen_ignores_ack ──────────────────────────────────────────────────────
//
// RFC 9293 §3.10.7.2: In Listen state, any ACK is "unacceptable."
// Implementation: silently dropped (the dispatch layer sends RST for
// unmatched ports; the socket-level Listen handler only acts on SYN).
#[test]
fn listen_ignores_ack() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut np = setup_network_pair()
        .profile(LinkProfile::leased_line_100m());
    let cfg = TcpConfig::default();

    let listener = TcpSocket::accept(
        np.iface_b(),
        "10.0.0.2:80".parse().unwrap(),
        |_| {}, |_| {}, cfg,
    )?;
    let ib = np.add_tcp_b(listener);

    assert_ok!(np.tcp_b(ib).state == State::Listen, "B not in Listen");

    // Inject a pure ACK (no SYN) into the listening socket.
    let ack = build_tcp_data(
        np.mac_a, np.mac_b,
        np.ip_a,  np.ip_b,
        12345, 80,
        1000, 1,
        b"",
    );
    np.inject_to_b(ack);
    np.transfer_one();

    assert_ok!(
        np.tcp_b(ib).state == State::Listen,
        "B left Listen after stray ACK: {:?}", np.tcp_b(ib).state
    );

    Ok(())
}

// ── listen_ignores_rst ──────────────────────────────────────────────────────
//
// RFC 9293 §3.10.7.2: RST in Listen must be ignored.  The socket stays in
// Listen and no response is sent.
#[test]
fn listen_ignores_rst() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut np = setup_network_pair()
        .profile(LinkProfile::leased_line_100m());
    let cfg = TcpConfig::default();

    let listener = TcpSocket::accept(
        np.iface_b(),
        "10.0.0.2:80".parse().unwrap(),
        |_| {}, |_| {}, cfg,
    )?;
    let ib = np.add_tcp_b(listener);

    np.clear_capture();
    let rst = build_tcp_data_with_flags(
        np.mac_a, np.mac_b,
        np.ip_a,  np.ip_b,
        12345, 80,
        1000, 0,
        0x04, // RST
        65535,
        b"",
    );
    np.inject_to_b(rst);
    np.transfer_one();

    assert_ok!(
        np.tcp_b(ib).state == State::Listen,
        "B left Listen after RST: {:?}", np.tcp_b(ib).state
    );

    // No response should be sent to a RST.
    let cap = np.drain_captured();
    let b_sent = cap.tcp().from_b().count();
    assert_ok!(b_sent == 0, "B sent {b_sent} frame(s) in response to RST in Listen");

    Ok(())
}

// ── listen_ignores_data_only ────────────────────────────────────────────────
//
// RFC 9293 §3.10.7.2: In Listen, only a SYN (without ACK) triggers a
// transition to SynReceived.  A data-only segment (no SYN, no ACK) is
// silently dropped.
#[test]
fn listen_ignores_data_only() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut np = setup_network_pair()
        .profile(LinkProfile::leased_line_100m());
    let cfg = TcpConfig::default();

    let listener = TcpSocket::accept(
        np.iface_b(),
        "10.0.0.2:80".parse().unwrap(),
        |_| {}, |_| {}, cfg,
    )?;
    let ib = np.add_tcp_b(listener);

    np.clear_capture();
    // PSH-only data segment (no SYN, no ACK).
    let data = build_tcp_data_with_flags(
        np.mac_a, np.mac_b,
        np.ip_a,  np.ip_b,
        12345, 80,
        1000, 0,
        0x08, // PSH
        65535,
        b"stray-data",
    );
    np.inject_to_b(data);
    np.transfer_one();

    assert_ok!(
        np.tcp_b(ib).state == State::Listen,
        "B left Listen after data-only segment: {:?}", np.tcp_b(ib).state
    );

    Ok(())
}

// ── syn_received_ignores_bad_ack ────────────────────────────────────────────
//
// RFC 9293 §3.10.7.3: In SynReceived, an ACK with ack outside
// (SND.UNA, SND.NXT] is unacceptable.  The socket must stay in SynReceived.
#[test]
fn syn_received_ignores_bad_ack() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut np = setup_network_pair()
        .profile(LinkProfile::leased_line_100m());
    let cfg = TcpConfig::default();

    let listener = TcpSocket::accept(
        np.iface_b(),
        "10.0.0.2:80".parse().unwrap(),
        |_| {}, |_| {}, cfg,
    )?;
    let ib = np.add_tcp_b(listener);

    // Send SYN to move B from Listen → SynReceived.
    let syn = build_tcp_syn(
        np.mac_a, np.mac_b,
        np.ip_a,  np.ip_b,
        12345, 80,
        5000, 0,
        0x02, // SYN
        Some(1460), None, None, false,
    );
    np.inject_to_b(syn);
    np.transfer_one();

    assert_ok!(
        np.tcp_b(ib).state == State::SynReceived,
        "B not in SynReceived after SYN: {:?}", np.tcp_b(ib).state
    );

    // Inject ACK with wrong ack number (0 — outside valid range).
    let bad_ack = build_tcp_data(
        np.mac_a, np.mac_b,
        np.ip_a,  np.ip_b,
        12345, 80,
        5001, 0, // ack=0, which is not in (SND.UNA, SND.NXT]
        b"",
    );
    np.inject_to_b(bad_ack);
    np.transfer_one();

    assert_ok!(
        np.tcp_b(ib).state == State::SynReceived,
        "B left SynReceived after bad ACK: {:?}", np.tcp_b(ib).state
    );

    Ok(())
}

// ── established_rejects_no_ack_data ─────────────────────────────────────────
//
// RFC 9293 §3.10.7.4 step 5: in synchronized states, if the ACK bit is off,
// drop the segment.  Data-only segments (no ACK, no SYN) must not deliver
// payload or advance rcv_nxt.
#[test]
fn established_rejects_no_ack_data() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    let rcv_nxt = pair.tcp_b().rcv_nxt();
    let b_snd_nxt = pair.tcp_b().snd_nxt();

    // Inject data segment without ACK flag (PSH only) via NetworkPair
    // to bypass TcpSocketPair's TS patcher (we want a raw non-ACK frame).
    // Include TS option so the missing-TS guard doesn't reject it first.
    let frame = crate::packet::build_tcp_data_with_ts(
        pair.mac_a, pair.mac_b,
        pair.ip_a,  pair.ip_b,
        12345, 80,
        rcv_nxt, b_snd_nxt,
        pair.clock_a.monotonic_ms() as u32,
        pair.tcp_a().ts_recent(),
        b"no-ack-data",
    );
    // Clear the ACK flag (byte 47, bit 4).
    let mut frame = frame;
    frame[47] &= !0x10; // clear ACK
    frame[47] |= 0x08;  // set PSH
    crate::packet::recompute_frame_tcp_checksum(&mut frame);
    pair.net.inject_to_b(frame);
    pair.transfer_one();

    let rcv_nxt_after = pair.tcp_b().rcv_nxt();
    assert_ok!(
        rcv_nxt_after == rcv_nxt,
        "rcv_nxt advanced ({rcv_nxt} → {rcv_nxt_after}) for data segment without ACK bit"
    );

    Ok(())
}

// ── established_rejects_ack_beyond_snd_nxt ──────────────────────────────────
//
// RFC 9293 §3.10.7.4 step 5: if SEG.ACK > SND.NXT, send an ACK and drop.
// An ACK acknowledging bytes the peer never sent must not update snd_una.
#[test]
fn established_rejects_ack_beyond_snd_nxt() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    let snd_una_before = pair.tcp_b().snd_una();
    let b_snd_nxt = pair.tcp_b().snd_nxt();
    let a_rcv_nxt = pair.tcp_a().rcv_nxt();

    // Inject ACK with ack far beyond B's snd_nxt.
    let bad_ack = crate::packet::build_tcp_data_with_ts(
        pair.mac_a, pair.mac_b,
        pair.ip_a,  pair.ip_b,
        12345, 80,
        a_rcv_nxt,
        b_snd_nxt.wrapping_add(1000), // ack > snd_nxt
        pair.clock_a.monotonic_ms() as u32,
        pair.tcp_a().ts_recent(),
        b"",
    );
    pair.net.inject_to_b(bad_ack);
    pair.transfer_one();

    // snd_una must NOT advance — the ACK was rejected.
    let snd_una_after = pair.tcp_b().snd_una();
    assert_ok!(
        snd_una_after == snd_una_before,
        "snd_una advanced ({snd_una_before} → {snd_una_after}) after ACK > SND.NXT"
    );

    // B should have sent a corrective ACK (RFC 9293 §3.10.7.4 step 5).
    let cap = pair.drain_captured();
    let corrective = cap.tcp().from_b()
        .with_tcp_flags(TcpFlags::ACK)
        .count();
    assert_ok!(corrective > 0, "B did not send corrective ACK for ACK > SND.NXT");

    Ok(())
}

// ── rst_at_zero_window ──────────────────────────────────────────────────────
//
// RFC 5961 §3.2: exact-match RST (SEQ == RCV.NXT) must reset even when the
// advertised receive window is zero (recv_buf full).
#[test]
fn rst_at_zero_window() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .recv_buf_max(100)
        .profile(LinkProfile::leased_line_100m())
        .connect();

    let rcv_nxt = pair.tcp_b().rcv_nxt();
    let b_snd_nxt = pair.tcp_b().snd_nxt();

    // Fill B's recv_buf to zero window (inject 100 bytes, don't drain).
    let fill = crate::packet::build_tcp_data_with_ts(
        pair.mac_a, pair.mac_b,
        pair.ip_a,  pair.ip_b,
        12345, 80,
        rcv_nxt, b_snd_nxt,
        0, 0,
        &vec![0xAAu8; 100],
    );
    pair.inject_to_b(fill);
    pair.transfer_one();
    assert_ok!(
        pair.tcp_b().rcv_nxt() == rcv_nxt + 100,
        "fill not accepted"
    );

    // Inject exact-match RST at B's rcv_nxt (now rcv_nxt + 100).
    let rst = build_tcp_rst(
        pair.mac_a, pair.mac_b,
        pair.ip_a,  pair.ip_b,
        12345, 80,
        rcv_nxt + 100,
    );
    pair.inject_to_b(rst);
    pair.transfer_one();

    assert_state(pair.tcp_b(), State::Closed, "B Closed after RST at zero window")?;
    assert_error_fired(pair.tcp_b(), TcpError::Reset, "B error = Reset")?;

    Ok(())
}

// ── data_on_completing_ack ──────────────────────────────────────────────────
//
// RFC 793 §3.4: the completing ACK in a 3-way handshake may carry piggybacked
// data.  The server must deliver it after transitioning to Established.
#[test]
fn data_on_completing_ack() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut np = setup_network_pair()
        .profile(LinkProfile::leased_line_100m());
    let cfg = TcpConfig::default();

    // B listens.
    let listener = TcpSocket::accept(
        np.iface_b(),
        "10.0.0.2:80".parse().unwrap(),
        |_| {}, |_| {}, cfg,
    )?;
    let ib = np.add_tcp_b(listener);

    // A sends SYN.
    let isn_a: u32 = 5000;
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
    assert_ok!(np.tcp_b(ib).state == State::SynReceived, "B not SynReceived");

    // Capture B's SYN-ACK to get B's ISN.
    let cap = np.drain_captured();
    let syn_ack = cap.tcp().from_b()
        .find(|f| f.tcp.flags.has(TcpFlags::SYN) && f.tcp.flags.has(TcpFlags::ACK))
        .ok_or_else(|| crate::assert::TestFail::new("no SYN-ACK"))?;
    let isn_b = syn_ack.tcp.seq;

    // Send completing ACK with piggybacked data "hello".
    let ack_with_data = crate::packet::build_tcp_data_with_ts(
        np.mac_a, np.mac_b,
        np.ip_a,  np.ip_b,
        12345, 80,
        isn_a + 1,     // seq after SYN
        isn_b + 1,     // ack B's SYN
        0, 0,
        b"hello",
    );
    np.inject_to_b(ack_with_data);
    np.transfer_one();

    assert_ok!(
        np.tcp_b(ib).state == State::Established,
        "B not Established after completing ACK: {:?}", np.tcp_b(ib).state
    );

    // Verify B's rcv_nxt advanced past the piggybacked data.
    let expected_rcv_nxt = isn_a + 1 + 5; // SYN + "hello"
    assert_ok!(
        np.tcp_b(ib).rcv_nxt() == expected_rcv_nxt,
        "rcv_nxt ({}) != expected ({expected_rcv_nxt}) — piggybacked data not delivered",
        np.tcp_b(ib).rcv_nxt()
    );

    // Verify payload was delivered to the application (not just rcv_nxt advanced).
    let mut buf = [0u8; 64];
    let n = np.tcp_b_mut(ib).recv(&mut buf);
    assert_ok!(n == Some(5), "recv returned {:?}, expected Some(5)", n);
    assert_ok!(&buf[..5] == b"hello", "payload mismatch: {:?}", &buf[..5]);

    Ok(())
}

// ── syn_challenge_ack_in_fin_wait2 ──────────────────────────────────────────
//
// RFC 5961 §4: an in-window SYN in a synchronized teardown state must elicit
// a challenge ACK and must NOT perturb state.
#[test]
fn syn_challenge_ack_in_fin_wait2() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    pair.tcp_a_mut().close()?;
    pair.transfer_while(|p| p.tcp_a(0).state != State::FinWait2);
    assert_state(pair.tcp_a(), State::FinWait2, "A FinWait2")?;

    let rcv_nxt = pair.tcp_a().rcv_nxt();
    let a_snd_nxt = pair.tcp_a().snd_nxt();
    let challenge_before = pair.tcp_a().challenge_ack_count();

    // Inject in-window SYN from B.
    let syn = build_tcp_syn(
        pair.mac_b, pair.mac_a,
        pair.ip_b,  pair.ip_a,
        80, 12345,
        rcv_nxt,
        a_snd_nxt,
        0x02, // SYN
        Some(1460), None, None, false,
    );
    pair.inject_to_a(syn);
    pair.transfer_one();

    // State must NOT change.
    assert_state(pair.tcp_a(), State::FinWait2, "A still FinWait2 after SYN")?;

    // Challenge ACK must have been sent.
    let challenge_after = pair.tcp_a().challenge_ack_count();
    assert_ok!(
        challenge_after > challenge_before,
        "no challenge ACK for SYN in FinWait2 ({challenge_before} → {challenge_after})"
    );

    Ok(())
}

// ── rst_in_syn_received ─────────────────────────────────────────────────────
//
// RFC 9293 §3.10.7.3: RST in SynReceived with SEQ == RCV.NXT aborts the
// connection back to Listen (passive open) or Closed (active open).
// Our implementation always goes to Closed.
#[test]
fn rst_in_syn_received() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut np = setup_network_pair()
        .profile(LinkProfile::leased_line_100m());
    let cfg = TcpConfig::default();

    let listener = TcpSocket::accept(
        np.iface_b(),
        "10.0.0.2:80".parse().unwrap(),
        |_| {}, |_| {}, cfg,
    )?;
    let ib = np.add_tcp_b(listener);

    // Send SYN → B enters SynReceived.
    let isn_a: u32 = 7000;
    let syn = build_tcp_syn(
        np.mac_a, np.mac_b,
        np.ip_a,  np.ip_b,
        12345, 80,
        isn_a, 0, 0x02,
        Some(1460), None, None, false,
    );
    np.inject_to_b(syn);
    np.transfer_one();
    assert_ok!(np.tcp_b(ib).state == State::SynReceived, "B not SynReceived");

    let rcv_nxt = np.tcp_b(ib).rcv_nxt();

    // Inject exact-match RST.
    let rst = build_tcp_rst(
        np.mac_a, np.mac_b,
        np.ip_a,  np.ip_b,
        12345, 80,
        rcv_nxt,
    );
    np.inject_to_b(rst);
    np.transfer_one();

    assert_ok!(
        np.tcp_b(ib).state == State::Closed,
        "B not Closed after RST in SynReceived: {:?}", np.tcp_b(ib).state
    );

    Ok(())
}

// ── rst_in_fin_wait2 ────────────────────────────────────────────────────────
//
// RFC 9293 §3.10.7.4: exact-match RST in a teardown state resets to Closed.
// Tests the shared RST handler from a non-Established state.
#[test]
fn rst_in_fin_wait2() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    pair.tcp_a_mut().close()?;
    pair.transfer_while(|p| p.tcp_a(0).state != State::FinWait2);
    assert_state(pair.tcp_a(), State::FinWait2, "A FinWait2")?;

    let rcv_nxt = pair.tcp_a().rcv_nxt();
    let rst = build_tcp_rst(
        pair.mac_b, pair.mac_a,
        pair.ip_b,  pair.ip_a,
        80, 12345,
        rcv_nxt,
    );
    pair.inject_to_a(rst);
    pair.transfer_one();

    assert_state(pair.tcp_a(), State::Closed, "A Closed after RST in FinWait2")?;
    assert_error_fired(pair.tcp_a(), TcpError::Reset, "A error = Reset")?;

    Ok(())
}

// ── fin_retransmit_exhaustion ───────────────────────────────────────────────
//
// RFC 9293 §3.8: after max_retransmits RTO expirations, the connection is
// aborted with TcpError::Timeout.  Verify this works in FinWait1 (FIN
// retransmit), not just Established.
#[test]
fn fin_retransmit_exhaustion() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .rto_min_ms(10)
        .max_retransmits(3)
        .profile(LinkProfile::leased_line_100m())
        .connect();

    // Blackhole B→A so FIN is never ACKed.
    pair.blackhole_to_a();
    pair.tcp_a_mut().close()?;
    pair.transfer_one(); // FIN departs

    assert_state(pair.tcp_a(), State::FinWait1, "A FinWait1")?;

    // Drive RTO retransmits until max_retransmits exhausted.
    for _ in 0..10 {
        let rto = pair.tcp_a().rto_ms().max(10);
        pair.advance_both(rto as i64 + 5);
        pair.transfer_one();
        if pair.tcp_a().state == State::Closed { break; }
    }

    assert_state(pair.tcp_a(), State::Closed, "A Closed after FIN retransmit exhaustion")?;
    assert_error_fired(pair.tcp_a(), TcpError::Timeout, "A error = Timeout")?;

    Ok(())
}

// ── send_in_syn_received ────────────────────────────────────────────────────
//
// RFC 9293 §3.10.2: send() in SynReceived queues data until Established.
// The passive opener (server) calls send() before the completing ACK arrives.
#[test]
fn send_in_syn_received() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut np = setup_network_pair()
        .profile(LinkProfile::leased_line_100m());
    let cfg = TcpConfig::default();

    // B listens, A connects actively.
    let listener = TcpSocket::accept(
        np.iface_b(),
        "10.0.0.2:80".parse().unwrap(),
        |_| {}, |_| {}, cfg.clone(),
    )?;
    let ib = np.add_tcp_b(listener);

    let client = TcpSocket::connect_now(
        np.iface_a(),
        "10.0.0.1:12345".parse().unwrap(),
        "10.0.0.2:80".parse().unwrap(),
        Ipv4Addr::from([10, 0, 0, 2]),
        |_| {}, |_| {}, cfg,
    )?;
    let ia = np.add_tcp_a(client);

    // Drive until B enters SynReceived (SYN arrives, SYN-ACK sent).
    np.transfer_while(|p| p.tcp_b(ib).state != State::SynReceived);
    assert_ok!(np.tcp_b(ib).state == State::SynReceived, "B not SynReceived");

    // Queue data in SynReceived — must succeed.
    np.tcp_b_mut(ib).send(b"queued-in-syn-rcvd")?;
    assert_ok!(
        np.tcp_b(ib).send_buf_len() == 18,
        "data not queued in SynReceived: send_buf_len={}", np.tcp_b(ib).send_buf_len()
    );

    // Complete handshake and deliver queued data to A.
    let result = np.transfer();

    assert_ok!(
        np.tcp_b(ib).state == State::Established,
        "B not Established: {:?}", np.tcp_b(ib).state
    );
    assert_ok!(
        np.tcp_a(ia).state == State::Established,
        "A not Established: {:?}", np.tcp_a(ia).state
    );

    // Queued data must have been flushed.
    assert_ok!(
        np.tcp_b(ib).send_buf_len() == 0,
        "send_buf not drained after handshake: {}", np.tcp_b(ib).send_buf_len()
    );

    // Verify A received the queued data (application-level delivery).
    let received = result.a.get(&ia).map(|v| v.as_slice()).unwrap_or(&[]);
    assert_ok!(
        received == b"queued-in-syn-rcvd",
        "A did not receive queued data: got {:?}", received
    );

    Ok(())
}

// ── last_ack_rejects_stale_ack ──────────────────────────────────────────────
//
// RFC 9293 §3.10.7.4: LastAck → Closed only when ACK covers our FIN
// (seg.ack >= snd_nxt).  A stale ACK must not trigger premature close.
#[test]
fn last_ack_rejects_stale_ack() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    // B closes first → A enters CloseWait.
    pair.tcp_b_mut().close()?;
    pair.transfer_while(|p| p.tcp_a(0).state != State::CloseWait);
    assert_state(pair.tcp_a(), State::CloseWait, "A CloseWait")?;

    // A closes → LastAck (FIN sent, waiting for ACK).
    pair.blackhole_to_b(); // prevent B's ACK from reaching A
    pair.tcp_a_mut().close()?;
    pair.transfer_one(); // FIN departs
    assert_state(pair.tcp_a(), State::LastAck, "A LastAck")?;

    let snd_nxt = pair.tcp_a().snd_nxt();
    let rcv_nxt = pair.tcp_a().rcv_nxt();
    pair.clear_impairments();

    // Inject stale ACK (ack < snd_nxt — doesn't cover our FIN).
    let stale = crate::packet::build_tcp_data_with_ts(
        pair.mac_b, pair.mac_a,
        pair.ip_b,  pair.ip_a,
        80, 12345,
        rcv_nxt,
        snd_nxt.wrapping_sub(1), // stale: doesn't cover FIN
        0, 0,
        b"",
    );
    pair.inject_to_a(stale);
    pair.transfer_one();

    // Must still be in LastAck — stale ACK rejected, no error.
    assert_state(pair.tcp_a(), State::LastAck, "A still LastAck after stale ACK")?;
    assert_ok!(
        pair.tcp_a().last_error.is_none(),
        "error fired on stale ACK in LastAck — should be silently ignored"
    );

    // Positive path: inject valid ACK covering FIN → Closed.
    pair.clear_impairments();
    let valid = crate::packet::build_tcp_data_with_ts(
        pair.mac_b, pair.mac_a,
        pair.ip_b,  pair.ip_a,
        80, 12345,
        rcv_nxt,
        snd_nxt, // covers FIN
        0, 0,
        b"",
    );
    pair.inject_to_a(valid);
    pair.transfer_one();
    assert_state(pair.tcp_a(), State::Closed, "A Closed after valid ACK in LastAck")?;

    Ok(())
}

// ── closing_rejects_stale_ack ───────────────────────────────────────────────
//
// RFC 9293 §3.10.7.4: Closing → TimeWait only when ACK covers our FIN.
#[test]
fn closing_rejects_stale_ack() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    // Simultaneous close: both sides call close().
    pair.tcp_a_mut().close()?;
    pair.tcp_b_mut().close()?;
    // Drive until A reaches Closing (A's FIN not yet ACKed, B's FIN received).
    pair.transfer_while(|p| p.tcp_a(0).state != State::Closing);
    assert_state(pair.tcp_a(), State::Closing, "A Closing")?;

    let snd_nxt = pair.tcp_a().snd_nxt();
    let rcv_nxt = pair.tcp_a().rcv_nxt();

    // Inject stale ACK (doesn't cover our FIN).
    let stale = crate::packet::build_tcp_data_with_ts(
        pair.mac_b, pair.mac_a,
        pair.ip_b,  pair.ip_a,
        80, 12345,
        rcv_nxt,
        snd_nxt.wrapping_sub(1),
        0, 0,
        b"",
    );
    pair.inject_to_a(stale);
    pair.transfer_one();

    assert_state(pair.tcp_a(), State::Closing, "A still Closing after stale ACK")?;
    assert_ok!(
        pair.tcp_a().last_error.is_none(),
        "error fired on stale ACK in Closing"
    );

    Ok(())
}

// ── syn_challenge_ack_in_close_wait ─────────────────────────────────────────
//
// RFC 5961 §4: SYN challenge ACK in CloseWait (complement to FinWait2 test).
#[test]
fn syn_challenge_ack_in_close_wait() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    pair.tcp_b_mut().close()?;
    pair.transfer_while(|p| p.tcp_a(0).state != State::CloseWait);
    assert_state(pair.tcp_a(), State::CloseWait, "A CloseWait")?;

    let rcv_nxt = pair.tcp_a().rcv_nxt();
    let challenge_before = pair.tcp_a().challenge_ack_count();

    let syn = build_tcp_syn(
        pair.mac_b, pair.mac_a,
        pair.ip_b,  pair.ip_a,
        80, 12345,
        rcv_nxt, pair.tcp_a().snd_nxt(),
        0x02, Some(1460), None, None, false,
    );
    pair.inject_to_a(syn);
    pair.transfer_one();

    assert_state(pair.tcp_a(), State::CloseWait, "A still CloseWait after SYN")?;
    assert_ok!(
        pair.tcp_a().challenge_ack_count() > challenge_before,
        "no challenge ACK for SYN in CloseWait"
    );

    Ok(())
}

// ── rst_in_close_wait ───────────────────────────────────────────────────────
//
// RFC 9293 §3.10.7.4: exact-match RST in CloseWait resets to Closed.
#[test]
fn rst_in_close_wait() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    pair.tcp_b_mut().close()?;
    pair.transfer_while(|p| p.tcp_a(0).state != State::CloseWait);
    assert_state(pair.tcp_a(), State::CloseWait, "A CloseWait")?;

    let rcv_nxt = pair.tcp_a().rcv_nxt();
    let rst = build_tcp_rst(
        pair.mac_b, pair.mac_a,
        pair.ip_b,  pair.ip_a,
        80, 12345,
        rcv_nxt,
    );
    pair.inject_to_a(rst);
    pair.transfer_one();

    assert_state(pair.tcp_a(), State::Closed, "A Closed after RST in CloseWait")?;
    assert_error_fired(pair.tcp_a(), TcpError::Reset, "A error = Reset")?;

    Ok(())
}

// ── fin_retransmit_exhaustion_last_ack ──────────────────────────────────────
//
// RFC 9293 §3.8: max_retransmits timeout in LastAck aborts with Timeout.
// Complement to fin_retransmit_exhaustion (FinWait1).
#[test]
fn fin_retransmit_exhaustion_last_ack() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .rto_min_ms(10)
        .max_retransmits(3)
        .profile(LinkProfile::leased_line_100m())
        .connect();

    // B closes → A enters CloseWait.
    pair.tcp_b_mut().close()?;
    pair.transfer_while(|p| p.tcp_a(0).state != State::CloseWait);

    // Blackhole, then A closes → LastAck (FIN never ACKed).
    pair.blackhole_to_b();
    pair.tcp_a_mut().close()?;
    pair.transfer_one();
    assert_state(pair.tcp_a(), State::LastAck, "A LastAck")?;

    for _ in 0..10 {
        let rto = pair.tcp_a().rto_ms().max(10);
        pair.advance_both(rto as i64 + 5);
        pair.transfer_one();
        if pair.tcp_a().state == State::Closed { break; }
    }

    assert_state(pair.tcp_a(), State::Closed, "A Closed after LastAck retransmit exhaustion")?;
    assert_error_fired(pair.tcp_a(), TcpError::Timeout, "A error = Timeout")?;

    Ok(())
}

// ── syn_ack_retransmit ──────────────────────────────────────────────────────
//
// RFC 9293 §3.8.1: SYN-ACK retransmission.  B accepts, A sends SYN, B enters
// SynReceived and sends SYN-ACK.  Drop the SYN-ACK on the A side, advance
// past B's RTO, and verify B retransmits the SYN-ACK.
#[test]
fn syn_ack_retransmit() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut np = setup_network_pair()
        .profile(LinkProfile::leased_line_100m());
    let cfg = TcpConfig::default().rto_min_ms(50);

    // B listens.
    let server = TcpSocket::accept(
        np.iface_b(),
        "10.0.0.2:80".parse().unwrap(),
        |_| {}, |_| {}, cfg,
    )?;
    let ib = np.add_tcp_b(server);

    // Drop all frames toward A so SYN-ACK never arrives.
    np.add_impairment_to_a(Impairment::Drop(PacketSpec::any()));

    // Inject SYN from A.
    let isn_a = 0x6000_0000u32;
    let syn = build_tcp_syn(
        np.mac_a, np.mac_b,
        np.ip_a,  np.ip_b,
        12345, 80,
        isn_a, 0,
        0x02,
        Some(1460), Some(4),
        Some((100, 0)),
        true,
    );
    np.inject_to_b(syn);
    np.transfer_one();

    assert_state(np.tcp_b(ib), State::SynReceived, "B should be in SynReceived")?;

    // Count initial SYN-ACKs.
    let cap = np.drain_captured();
    let initial_synacks: usize = cap.all_tcp().from_b()
        .filter(|f| f.tcp.flags.has(TcpFlags::SYN) && f.tcp.flags.has(TcpFlags::ACK))
        .count();
    assert_ok!(initial_synacks >= 1, "B did not send initial SYN-ACK");

    // Advance past RTO so B retransmits SYN-ACK.
    np.clear_capture();
    np.advance_both(200); // well past rto_min_ms=50
    np.transfer_one();

    let cap2 = np.drain_captured();
    let retx_synacks: usize = cap2.all_tcp().from_b()
        .filter(|f| f.tcp.flags.has(TcpFlags::SYN) && f.tcp.flags.has(TcpFlags::ACK))
        .count();
    assert_ok!(
        retx_synacks >= 1,
        "B did not retransmit SYN-ACK after RTO (got {retx_synacks} SYN-ACKs)"
    );

    // B should still be in SynReceived.
    assert_state(np.tcp_b(ib), State::SynReceived, "B still SynReceived after SYN-ACK retransmit")?;

    Ok(())
}

// ── fin_on_completing_ack ───────────────────────────────────────────────────
//
// RFC 9293 §3.10.7.3: In SynReceived, a valid ACK moves to Established.
// If that same segment carries a FIN, the FIN is processed in the new
// Established state, transitioning immediately to CloseWait.
#[test]
fn fin_on_completing_ack() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut np = setup_network_pair()
        .profile(LinkProfile::leased_line_100m());
    let cfg = TcpConfig::default();

    // Drop RSTs from A (no A-side socket to handle SYN-ACK).
    np.add_impairment_to_b(Impairment::Drop(PacketSpec::matching(filter::tcp::rst())));

    let server = TcpSocket::accept(
        np.iface_b(),
        "10.0.0.2:80".parse().unwrap(),
        |_| {}, |_| {}, cfg,
    )?;
    let ib = np.add_tcp_b(server);

    // Inject SYN from A.
    let isn_a = 0x7000_0000u32;
    let syn = build_tcp_syn(
        np.mac_a, np.mac_b,
        np.ip_a,  np.ip_b,
        12345, 80,
        isn_a, 0,
        0x02,
        Some(1460), Some(4),
        Some((100, 0)),
        true,
    );
    np.inject_to_b(syn);
    np.transfer_one();

    assert_state(np.tcp_b(ib), State::SynReceived, "B SynReceived after SYN")?;

    let cap = np.drain_captured();
    let syn_ack = cap.tcp().from_b()
        .with_tcp_flags(TcpFlags::SYN)
        .with_tcp_flags(TcpFlags::ACK)
        .next()
        .ok_or_else(|| crate::assert::TestFail::new("no SYN-ACK from B"))?;
    let b_isn = syn_ack.tcp.seq;
    let b_tsval = syn_ack.tcp.opts.timestamps.map(|(v, _)| v).unwrap_or(0);

    // Build completing ACK with FIN flag (ACK|FIN).
    let ack_fin = build_tcp_data_with_ts(
        np.mac_a, np.mac_b,
        np.ip_a,  np.ip_b,
        12345, 80,
        isn_a + 1,
        b_isn + 1,
        200,        // TSval
        b_tsval,    // TSecr echoes B's TSval
        &[],
    );
    // Patch flags: set FIN|ACK (0x11).
    let mut ack_fin = ack_fin;
    ack_fin[47] = 0x11; // FIN|ACK
    crate::packet::recompute_frame_tcp_checksum(&mut ack_fin);

    np.inject_to_b(ack_fin);
    np.transfer_one();

    // B should have transitioned: SynReceived → Established → CloseWait.
    assert_state(np.tcp_b(ib), State::CloseWait, "B should be CloseWait after ACK+FIN")?;

    Ok(())
}

// ── rst_in_closing ──────────────────────────────────────────────────────────
//
// RFC 9293 §3.5.3 (Reset Processing): RST with SEQ == RCV.NXT in Closing
// state must immediately close the connection.
//
// Drive to Closing via simultaneous close: both sides call close() with
// blackholed links, then manually deliver cross-FINs so both reach Closing
// (FIN received, own FIN not yet ACKed).  Inject exact RST to verify Closed.
#[test]
fn rst_in_closing() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    // Record seq/ack before closing.
    let a_snd_nxt = pair.tcp_a().snd_nxt();
    let b_snd_nxt = pair.tcp_b().snd_nxt();

    // Blackhole both directions so nothing crosses.
    pair.blackhole_both();

    // Both sides close → FinWait1 (FINs queued but blackholed).
    pair.tcp_a_mut().close()?;
    pair.tcp_b_mut().close()?;
    pair.transfer_one();

    assert_state(pair.tcp_a(), State::FinWait1, "A FinWait1")?;
    assert_state(pair.tcp_b(), State::FinWait1, "B FinWait1")?;

    // Build cross-FINs and inject directly (bypassing impairments).
    // B's FIN → A: FIN|ACK from B, seq=b_snd_nxt, ack=a_snd_nxt
    let fin_b_to_a = build_tcp_data_with_ts(
        pair.mac_b, pair.mac_a,
        pair.ip_b,  pair.ip_a,
        80, 12345,
        b_snd_nxt, a_snd_nxt,
        pair.clock_b.monotonic_ms() as u32,
        pair.tcp_b().ts_recent(),
        &[],
    );
    let mut fin_b_to_a = fin_b_to_a;
    fin_b_to_a[47] = 0x11; // FIN|ACK
    crate::packet::recompute_frame_tcp_checksum(&mut fin_b_to_a);
    pair.net.inject_to_a(fin_b_to_a);

    // A's FIN → B: FIN|ACK from A, seq=a_snd_nxt, ack=b_snd_nxt
    let fin_a_to_b = build_tcp_data_with_ts(
        pair.mac_a, pair.mac_b,
        pair.ip_a,  pair.ip_b,
        12345, 80,
        a_snd_nxt, b_snd_nxt,
        pair.clock_a.monotonic_ms() as u32,
        pair.tcp_a().ts_recent(),
        &[],
    );
    let mut fin_a_to_b = fin_a_to_b;
    fin_a_to_b[47] = 0x11; // FIN|ACK
    crate::packet::recompute_frame_tcp_checksum(&mut fin_a_to_b);
    pair.net.inject_to_b(fin_a_to_b);

    pair.transfer_one();

    // Both should be in Closing (received peer FIN, own FIN not yet ACKed).
    assert_state(pair.tcp_a(), State::Closing, "A Closing")?;
    assert_state(pair.tcp_b(), State::Closing, "B Closing")?;

    // Inject exact-match RST to A.
    {
        let rcv_nxt = pair.tcp_a().rcv_nxt();
        let rst = build_tcp_rst(
            pair.mac_b, pair.mac_a,
            pair.ip_b,  pair.ip_a,
            80, 12345,
            rcv_nxt,
        );
        pair.net.inject_to_a(rst);
        pair.transfer_one();
        assert_state(pair.tcp_a(), State::Closed, "A Closed after RST in Closing")?;
        assert_error_fired(pair.tcp_a(), TcpError::Reset, "A error = Reset")?;
    }

    Ok(())
}

// ── rst_in_last_ack ─────────────────────────────────────────────────────────
//
// RFC 9293 §3.5.3 (Reset Processing): RST with SEQ == RCV.NXT in LastAck
// state must immediately close the connection.
//
// B closes first → A enters CloseWait, A closes → LastAck.  Blackhole
// B→A so B's final ACK never arrives, leaving A in LastAck.  Inject RST.
#[test]
fn rst_in_last_ack() -> TestResult {
    use rawket::bridge::LinkProfile;
    let mut pair = setup_tcp_pair()
        .profile(LinkProfile::leased_line_100m())
        .connect();

    // B closes → A enters CloseWait.
    pair.tcp_b_mut().close()?;
    pair.transfer_while(|p| p.tcp_a(0).state != State::CloseWait);
    assert_state(pair.tcp_a(), State::CloseWait, "A CloseWait")?;

    // Blackhole B→A so B's ACK of A's FIN never arrives.
    pair.blackhole_to_a();

    // A closes → LastAck (FIN sent but not ACKed because blackholed).
    pair.tcp_a_mut().close()?;
    pair.transfer_one();
    assert_state(pair.tcp_a(), State::LastAck, "A LastAck")?;

    // Inject exact-match RST from B.
    let rcv_nxt = pair.tcp_a().rcv_nxt();
    let rst = build_tcp_rst(
        pair.mac_b, pair.mac_a,
        pair.ip_b,  pair.ip_a,
        80, 12345,
        rcv_nxt,
    );
    pair.net.inject_to_a(rst);
    pair.transfer_one();

    assert_state(pair.tcp_a(), State::Closed, "A Closed after RST in LastAck")?;

    Ok(())
}
