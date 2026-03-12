use rawket::tcp::{State, TcpFlags, TcpSocket};
use crate::{
    assert::{assert_timestamps_present, assert_state, TestFail},
    assert_ok,
    capture::ParsedFrameExt,
    harness::{fast_tcp_cfg, setup_network_pair, setup_tcp_pair},
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
