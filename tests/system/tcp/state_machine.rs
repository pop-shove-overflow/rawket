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
    packet::{build_tcp_data, build_tcp_data_with_flags, build_tcp_rst, build_tcp_syn,
             build_udp_data},
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
