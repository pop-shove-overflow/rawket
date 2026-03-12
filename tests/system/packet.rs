#![allow(dead_code, clippy::too_many_arguments)]
// Ethernet+IPv4+TCP/UDP/ICMP frame builders for rawket system tests.
//
// All builders return a fully-checksummed `Vec<u8>` ready for injection into
// the test harness via `Pair::inject_to_a` / `inject_to_b`.

// ── Checksum helpers ──────────────────────────────────────────────────────────

fn internet_checksum(data: &[u8]) -> u16 {
    let mut acc: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        acc += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        acc += (data[i] as u32) << 8;
    }
    while acc >> 16 != 0 {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    !(acc as u16)
}

fn tcp_checksum(src_ip: [u8; 4], dst_ip: [u8; 4], tcp_seg: &[u8]) -> u16 {
    let len = tcp_seg.len() as u16;
    let mut pseudo = [0u8; 12];
    pseudo[0..4].copy_from_slice(&src_ip);
    pseudo[4..8].copy_from_slice(&dst_ip);
    pseudo[8] = 0;
    pseudo[9] = 6; // TCP
    pseudo[10..12].copy_from_slice(&len.to_be_bytes());

    let mut acc: u32 = 0;
    for chunk in pseudo.chunks(2) {
        acc += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    let mut i = 0;
    while i + 1 < tcp_seg.len() {
        acc += u16::from_be_bytes([tcp_seg[i], tcp_seg[i + 1]]) as u32;
        i += 2;
    }
    if i < tcp_seg.len() {
        acc += (tcp_seg[i] as u32) << 8;
    }
    while acc >> 16 != 0 {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    !(acc as u16)
}

fn udp_checksum(src_ip: [u8; 4], dst_ip: [u8; 4], udp_seg: &[u8]) -> u16 {
    let len = udp_seg.len() as u16;
    let mut pseudo = [0u8; 12];
    pseudo[0..4].copy_from_slice(&src_ip);
    pseudo[4..8].copy_from_slice(&dst_ip);
    pseudo[8] = 0;
    pseudo[9] = 17; // UDP
    pseudo[10..12].copy_from_slice(&len.to_be_bytes());

    let mut acc: u32 = 0;
    for chunk in pseudo.chunks(2) {
        acc += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    let mut i = 0;
    while i + 1 < udp_seg.len() {
        acc += u16::from_be_bytes([udp_seg[i], udp_seg[i + 1]]) as u32;
        i += 2;
    }
    if i < udp_seg.len() {
        acc += (udp_seg[i] as u32) << 8;
    }
    while acc >> 16 != 0 {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    !(acc as u16)
}

/// Recompute the TCP checksum of an Ethernet frame in-place.
pub fn recompute_frame_tcp_checksum(frame: &mut [u8]) {
    let src_ip: [u8; 4] = frame[26..30].try_into().unwrap();
    let dst_ip: [u8; 4] = frame[30..34].try_into().unwrap();
    frame[50] = 0;
    frame[51] = 0;
    let cksum = tcp_checksum(src_ip, dst_ip, &frame[34..]);
    frame[50] = (cksum >> 8) as u8;
    frame[51] = cksum as u8;
}

// ── TCP builders ──────────────────────────────────────────────────────────────

/// Build an Ethernet+IPv4+TCP data frame (ACK flag) with a zeroed Timestamps
/// option.  TSval and TSecr are set to 0; `TcpSocketPair::inject_to_a/b` will
/// patch them to valid clock-derived values before delivery.
pub fn build_tcp_data(
    src_mac:  [u8; 6],
    dst_mac:  [u8; 6],
    src_ip:   [u8; 4],
    dst_ip:   [u8; 4],
    src_port: u16,
    dst_port: u16,
    seq:      u32,
    ack_num:  u32,
    payload:  &[u8],
) -> Vec<u8> {
    let tcp_opts_len = 12; // NOP NOP TS(10)
    let tcp_hdr  = 20 + tcp_opts_len;
    let ip_len   = 20 + tcp_hdr + payload.len();
    let total    = 14 + ip_len;
    let mut frame = vec![0u8; total];

    frame[0..6].copy_from_slice(&dst_mac);
    frame[6..12].copy_from_slice(&src_mac);
    frame[12..14].copy_from_slice(&[0x08, 0x00]);

    frame[14] = 0x45;
    frame[15] = 0x00;
    frame[16..18].copy_from_slice(&(ip_len as u16).to_be_bytes());
    frame[18..20].copy_from_slice(&[0x00, 0x00]);
    frame[20..22].copy_from_slice(&[0x40, 0x00]);
    frame[22] = 64;
    frame[23] = 6;
    frame[26..30].copy_from_slice(&src_ip);
    frame[30..34].copy_from_slice(&dst_ip);
    let ip_cksum = internet_checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&ip_cksum.to_be_bytes());

    frame[34..36].copy_from_slice(&src_port.to_be_bytes());
    frame[36..38].copy_from_slice(&dst_port.to_be_bytes());
    frame[38..42].copy_from_slice(&seq.to_be_bytes());
    frame[42..46].copy_from_slice(&ack_num.to_be_bytes());
    frame[46] = 0x80; // data_offset = 8 (32 bytes)
    frame[47] = 0x10; // ACK flag
    frame[48..50].copy_from_slice(&65535u16.to_be_bytes());
    // Timestamps option: NOP NOP kind=8 len=10 TSval=0 TSecr=0
    frame[54] = 0x01; frame[55] = 0x01;
    frame[56] = 0x08; frame[57] = 0x0a;
    // TSval [58..62] and TSecr [62..66] are already zero
    frame[66..66 + payload.len()].copy_from_slice(payload);

    let tcp_cksum = tcp_checksum(src_ip, dst_ip, &frame[34..total]);
    frame[50..52].copy_from_slice(&tcp_cksum.to_be_bytes());

    frame
}

/// Like `build_tcp_data` but appends a Window Scale option (for testing that
/// WS in non-SYN segments is ignored per RFC 7323 §2.2).
pub fn build_tcp_data_with_ws(
    src_mac:  [u8; 6],
    dst_mac:  [u8; 6],
    src_ip:   [u8; 4],
    dst_ip:   [u8; 4],
    src_port: u16,
    dst_port: u16,
    seq:      u32,
    ack_num:  u32,
    ws_shift: u8,
    payload:  &[u8],
) -> Vec<u8> {
    // Options: NOP NOP TS(10) NOP WS(3) = 16 bytes → data_offset = 9
    let tcp_opts_len = 16;
    let tcp_hdr  = 20 + tcp_opts_len;
    let ip_len   = 20 + tcp_hdr + payload.len();
    let total    = 14 + ip_len;
    let mut frame = vec![0u8; total];

    frame[0..6].copy_from_slice(&dst_mac);
    frame[6..12].copy_from_slice(&src_mac);
    frame[12..14].copy_from_slice(&[0x08, 0x00]);

    frame[14] = 0x45;
    frame[16..18].copy_from_slice(&(ip_len as u16).to_be_bytes());
    frame[20..22].copy_from_slice(&[0x40, 0x00]);
    frame[22] = 64;
    frame[23] = 6;
    frame[26..30].copy_from_slice(&src_ip);
    frame[30..34].copy_from_slice(&dst_ip);
    let ip_cksum = internet_checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&ip_cksum.to_be_bytes());

    frame[34..36].copy_from_slice(&src_port.to_be_bytes());
    frame[36..38].copy_from_slice(&dst_port.to_be_bytes());
    frame[38..42].copy_from_slice(&seq.to_be_bytes());
    frame[42..46].copy_from_slice(&ack_num.to_be_bytes());
    frame[46] = 0x90; // data_offset = 9 (36 bytes)
    frame[47] = 0x10; // ACK flag
    frame[48..50].copy_from_slice(&65535u16.to_be_bytes());
    // Timestamps option: NOP NOP kind=8 len=10 TSval=0 TSecr=0
    frame[54] = 0x01; frame[55] = 0x01;
    frame[56] = 0x08; frame[57] = 0x0a;
    // TSval [58..62] and TSecr [62..66] are already zero
    // Window Scale option: NOP kind=3 len=3 shift
    frame[66] = 0x01; // NOP
    frame[67] = 0x03; // kind = Window Scale
    frame[68] = 0x03; // len = 3
    frame[69] = ws_shift;

    frame[70..70 + payload.len()].copy_from_slice(payload);

    let tcp_cksum = tcp_checksum(src_ip, dst_ip, &frame[34..total]);
    frame[50..52].copy_from_slice(&tcp_cksum.to_be_bytes());

    frame
}

/// Build an Ethernet+IPv4+TCP frame with caller-specified flags and a zeroed
/// Timestamps option.  TSval and TSecr are set to 0; `TcpSocketPair::inject_to_a/b`
/// will patch them to valid clock-derived values before delivery.
pub fn build_tcp_data_with_flags(
    src_mac:  [u8; 6],
    dst_mac:  [u8; 6],
    src_ip:   [u8; 4],
    dst_ip:   [u8; 4],
    src_port: u16,
    dst_port: u16,
    seq:      u32,
    ack_num:  u32,
    flags:    u8,
    window:   u16,
    payload:  &[u8],
) -> Vec<u8> {
    let tcp_opts_len = 12; // NOP NOP TS(10)
    let tcp_hdr  = 20 + tcp_opts_len;
    let ip_len   = 20 + tcp_hdr + payload.len();
    let total    = 14 + ip_len;
    let mut frame = vec![0u8; total];

    frame[0..6].copy_from_slice(&dst_mac);
    frame[6..12].copy_from_slice(&src_mac);
    frame[12..14].copy_from_slice(&[0x08, 0x00]);

    frame[14] = 0x45;
    frame[15] = 0x00;
    frame[16..18].copy_from_slice(&(ip_len as u16).to_be_bytes());
    frame[18..20].copy_from_slice(&[0x00, 0x00]);
    frame[20..22].copy_from_slice(&[0x40, 0x00]);
    frame[22] = 64;
    frame[23] = 6;
    frame[26..30].copy_from_slice(&src_ip);
    frame[30..34].copy_from_slice(&dst_ip);
    let ip_cksum = internet_checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&ip_cksum.to_be_bytes());

    frame[34..36].copy_from_slice(&src_port.to_be_bytes());
    frame[36..38].copy_from_slice(&dst_port.to_be_bytes());
    frame[38..42].copy_from_slice(&seq.to_be_bytes());
    frame[42..46].copy_from_slice(&ack_num.to_be_bytes());
    frame[46] = 0x80; // data_offset = 8 (32 bytes)
    frame[47] = flags;
    frame[48..50].copy_from_slice(&window.to_be_bytes());
    // Timestamps option: NOP NOP kind=8 len=10 TSval=0 TSecr=0
    frame[54] = 0x01; frame[55] = 0x01;
    frame[56] = 0x08; frame[57] = 0x0a;
    // TSval [58..62] and TSecr [62..66] are already zero
    frame[66..66 + payload.len()].copy_from_slice(payload);

    let tcp_cksum = tcp_checksum(src_ip, dst_ip, &frame[34..total]);
    frame[50..52].copy_from_slice(&tcp_cksum.to_be_bytes());

    frame
}

/// Build a minimal Ethernet+IPv4+TCP RST frame (no options).
pub fn build_tcp_rst(
    src_mac:  [u8; 6],
    dst_mac:  [u8; 6],
    src_ip:   [u8; 4],
    dst_ip:   [u8; 4],
    src_port: u16,
    dst_port: u16,
    seq:      u32,
) -> Vec<u8> {
    let mut frame = vec![0u8; 54];

    frame[0..6].copy_from_slice(&dst_mac);
    frame[6..12].copy_from_slice(&src_mac);
    frame[12..14].copy_from_slice(&[0x08, 0x00]);

    frame[14] = 0x45;
    frame[15] = 0x00;
    frame[16..18].copy_from_slice(&40u16.to_be_bytes());
    frame[18..20].copy_from_slice(&[0x00, 0x00]);
    frame[20..22].copy_from_slice(&[0x40, 0x00]);
    frame[22] = 64;
    frame[23] = 6;
    frame[26..30].copy_from_slice(&src_ip);
    frame[30..34].copy_from_slice(&dst_ip);

    let ip_cksum = internet_checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&ip_cksum.to_be_bytes());

    frame[34..36].copy_from_slice(&src_port.to_be_bytes());
    frame[36..38].copy_from_slice(&dst_port.to_be_bytes());
    frame[38..42].copy_from_slice(&seq.to_be_bytes());
    frame[42..46].copy_from_slice(&0u32.to_be_bytes());
    frame[46] = 0x50;
    frame[47] = 0x04; // RST flag
    frame[48..50].copy_from_slice(&0u16.to_be_bytes());
    frame[52..54].copy_from_slice(&0u16.to_be_bytes());

    let tcp_cksum = tcp_checksum(src_ip, dst_ip, &frame[34..54]);
    frame[50..52].copy_from_slice(&tcp_cksum.to_be_bytes());

    frame
}

/// Build an Ethernet+IPv4+TCP SYN or SYN-ACK frame with selected TCP options.
pub fn build_tcp_syn(
    src_mac:      [u8; 6],
    dst_mac:      [u8; 6],
    src_ip:       [u8; 4],
    dst_ip:       [u8; 4],
    src_port:     u16,
    dst_port:     u16,
    seq:          u32,
    ack_num:      u32,
    base_flags:   u8,
    mss:          Option<u16>,
    window_scale: Option<u8>,
    timestamps:   Option<(u32, u32)>,
    sack_ok:      bool,
) -> Vec<u8> {
    let mut opts: Vec<u8> = Vec::new();
    if let Some(m) = mss {
        opts.extend_from_slice(&[0x02, 0x04, (m >> 8) as u8, m as u8]);
    }
    if let Some(ws) = window_scale {
        opts.extend_from_slice(&[0x03, 0x03, ws, 0x01]);
    }
    if sack_ok {
        opts.extend_from_slice(&[0x04, 0x02, 0x01, 0x01]);
    }
    if let Some((tsval, tsecr)) = timestamps {
        opts.push(0x01); opts.push(0x01);
        opts.push(0x08); opts.push(0x0a);
        opts.extend_from_slice(&tsval.to_be_bytes());
        opts.extend_from_slice(&tsecr.to_be_bytes());
    }
    while !opts.len().is_multiple_of(4) { opts.push(0x01); }

    let opts_len = opts.len();
    let tcp_hdr  = 20 + opts_len;
    let ip_len   = 20 + tcp_hdr;
    let total    = 14 + ip_len;
    let mut frame = vec![0u8; total];

    frame[0..6].copy_from_slice(&dst_mac);
    frame[6..12].copy_from_slice(&src_mac);
    frame[12..14].copy_from_slice(&[0x08, 0x00]);

    frame[14] = 0x45;
    frame[16..18].copy_from_slice(&(ip_len as u16).to_be_bytes());
    frame[20..22].copy_from_slice(&[0x40, 0x00]);
    frame[22] = 64; frame[23] = 6;
    frame[26..30].copy_from_slice(&src_ip);
    frame[30..34].copy_from_slice(&dst_ip);
    let ip_cksum = internet_checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&ip_cksum.to_be_bytes());

    frame[34..36].copy_from_slice(&src_port.to_be_bytes());
    frame[36..38].copy_from_slice(&dst_port.to_be_bytes());
    frame[38..42].copy_from_slice(&seq.to_be_bytes());
    frame[42..46].copy_from_slice(&ack_num.to_be_bytes());
    frame[46] = ((tcp_hdr / 4) as u8) << 4;
    frame[47] = base_flags;
    frame[48..50].copy_from_slice(&65535u16.to_be_bytes());
    frame[54..54 + opts_len].copy_from_slice(&opts);
    let tcp_cksum = tcp_checksum(src_ip, dst_ip, &frame[34..total]);
    frame[50..52].copy_from_slice(&tcp_cksum.to_be_bytes());

    frame
}

/// Build an Ethernet+IPv4+TCP data frame with a 12-byte Timestamps option.
pub fn build_tcp_data_with_ts(
    src_mac:  [u8; 6],
    dst_mac:  [u8; 6],
    src_ip:   [u8; 4],
    dst_ip:   [u8; 4],
    src_port: u16,
    dst_port: u16,
    seq:      u32,
    ack_num:  u32,
    ts_val:   u32,
    ts_ecr:   u32,
    payload:  &[u8],
) -> Vec<u8> {
    let tcp_opts_len = 12;
    let tcp_hdr  = 20 + tcp_opts_len;
    let ip_len   = 20 + tcp_hdr + payload.len();
    let total    = 14 + ip_len;
    let mut frame = vec![0u8; total];

    frame[0..6].copy_from_slice(&dst_mac);
    frame[6..12].copy_from_slice(&src_mac);
    frame[12..14].copy_from_slice(&[0x08, 0x00]);

    frame[14] = 0x45;
    frame[16..18].copy_from_slice(&(ip_len as u16).to_be_bytes());
    frame[20..22].copy_from_slice(&[0x40, 0x00]);
    frame[22] = 64; frame[23] = 6;
    frame[26..30].copy_from_slice(&src_ip);
    frame[30..34].copy_from_slice(&dst_ip);
    let ip_cksum = internet_checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&ip_cksum.to_be_bytes());

    frame[34..36].copy_from_slice(&src_port.to_be_bytes());
    frame[36..38].copy_from_slice(&dst_port.to_be_bytes());
    frame[38..42].copy_from_slice(&seq.to_be_bytes());
    frame[42..46].copy_from_slice(&ack_num.to_be_bytes());
    frame[46] = 0x80; // data_offset = 8 (32 bytes)
    frame[47] = 0x10; // ACK flag
    frame[48..50].copy_from_slice(&65535u16.to_be_bytes());
    frame[54] = 0x01; frame[55] = 0x01;
    frame[56] = 0x08; frame[57] = 0x0a;
    frame[58..62].copy_from_slice(&ts_val.to_be_bytes());
    frame[62..66].copy_from_slice(&ts_ecr.to_be_bytes());
    frame[66..66 + payload.len()].copy_from_slice(payload);
    let tcp_cksum = tcp_checksum(src_ip, dst_ip, &frame[34..total]);
    frame[50..52].copy_from_slice(&tcp_cksum.to_be_bytes());

    frame
}

/// Build an ACK frame with both Timestamps and SACK options.
pub fn build_tcp_data_with_sack_ts(
    src_mac:     [u8; 6],
    dst_mac:     [u8; 6],
    src_ip:      [u8; 4],
    dst_ip:      [u8; 4],
    src_port:    u16,
    dst_port:    u16,
    seq:         u32,
    ack_num:     u32,
    ts_val:      u32,
    ts_ecr:      u32,
    sack_blocks: &[(u32, u32)],
    payload:     &[u8],
) -> Vec<u8> {
    let ts_opts_len   = 12;
    let sack_opts_len = 4 + 8 * sack_blocks.len();
    let opts_len = ts_opts_len + sack_opts_len;
    let tcp_hdr  = 20 + opts_len;
    let ip_len   = 20 + tcp_hdr + payload.len();
    let total    = 14 + ip_len;
    let mut frame = vec![0u8; total];

    frame[0..6].copy_from_slice(&dst_mac);
    frame[6..12].copy_from_slice(&src_mac);
    frame[12..14].copy_from_slice(&[0x08, 0x00]);

    frame[14] = 0x45;
    frame[16..18].copy_from_slice(&(ip_len as u16).to_be_bytes());
    frame[20..22].copy_from_slice(&[0x40, 0x00]);
    frame[22] = 64; frame[23] = 6;
    frame[26..30].copy_from_slice(&src_ip);
    frame[30..34].copy_from_slice(&dst_ip);
    let ip_cksum = internet_checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&ip_cksum.to_be_bytes());

    frame[34..36].copy_from_slice(&src_port.to_be_bytes());
    frame[36..38].copy_from_slice(&dst_port.to_be_bytes());
    frame[38..42].copy_from_slice(&seq.to_be_bytes());
    frame[42..46].copy_from_slice(&ack_num.to_be_bytes());
    frame[46] = ((tcp_hdr / 4) as u8) << 4;
    frame[47] = 0x10; // ACK
    frame[48..50].copy_from_slice(&65535u16.to_be_bytes());

    let mut o = 54;
    frame[o] = 0x01; o += 1;
    frame[o] = 0x01; o += 1;
    frame[o] = 0x08; o += 1;
    frame[o] = 0x0a; o += 1;
    frame[o..o + 4].copy_from_slice(&ts_val.to_be_bytes()); o += 4;
    frame[o..o + 4].copy_from_slice(&ts_ecr.to_be_bytes()); o += 4;

    frame[o] = 0x01; o += 1;
    frame[o] = 0x01; o += 1;
    frame[o] = 0x05; o += 1;
    frame[o] = (2 + 8 * sack_blocks.len()) as u8; o += 1;
    for &(left, right) in sack_blocks {
        frame[o..o + 4].copy_from_slice(&left.to_be_bytes());  o += 4;
        frame[o..o + 4].copy_from_slice(&right.to_be_bytes()); o += 4;
    }

    frame[o..o + payload.len()].copy_from_slice(payload);

    let tcp_cksum = tcp_checksum(src_ip, dst_ip, &frame[34..total]);
    frame[50..52].copy_from_slice(&tcp_cksum.to_be_bytes());

    frame
}

pub fn build_tcp_data_with_sack(
    src_mac:     [u8; 6],
    dst_mac:     [u8; 6],
    src_ip:      [u8; 4],
    dst_ip:      [u8; 4],
    src_port:    u16,
    dst_port:    u16,
    seq:         u32,
    ack_num:     u32,
    sack_blocks: &[(u32, u32)],
    payload:     &[u8],
) -> Vec<u8> {
    let opts_len = 4 + 8 * sack_blocks.len();
    let tcp_hdr  = 20 + opts_len;
    let ip_len   = 20 + tcp_hdr + payload.len();
    let total    = 14 + ip_len;
    let mut frame = vec![0u8; total];

    frame[0..6].copy_from_slice(&dst_mac);
    frame[6..12].copy_from_slice(&src_mac);
    frame[12..14].copy_from_slice(&[0x08, 0x00]);

    frame[14] = 0x45;
    frame[16..18].copy_from_slice(&(ip_len as u16).to_be_bytes());
    frame[20..22].copy_from_slice(&[0x40, 0x00]);
    frame[22] = 64; frame[23] = 6;
    frame[26..30].copy_from_slice(&src_ip);
    frame[30..34].copy_from_slice(&dst_ip);
    let ip_cksum = internet_checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&ip_cksum.to_be_bytes());

    frame[34..36].copy_from_slice(&src_port.to_be_bytes());
    frame[36..38].copy_from_slice(&dst_port.to_be_bytes());
    frame[38..42].copy_from_slice(&seq.to_be_bytes());
    frame[42..46].copy_from_slice(&ack_num.to_be_bytes());
    frame[46] = ((tcp_hdr / 4) as u8) << 4;
    frame[47] = 0x10; // ACK
    frame[48..50].copy_from_slice(&65535u16.to_be_bytes());

    let mut o = 54;
    frame[o] = 0x01; o += 1;
    frame[o] = 0x01; o += 1;
    frame[o] = 0x05; o += 1;
    frame[o] = (2 + 8 * sack_blocks.len()) as u8; o += 1;
    for &(left, right) in sack_blocks {
        frame[o..o + 4].copy_from_slice(&left.to_be_bytes());  o += 4;
        frame[o..o + 4].copy_from_slice(&right.to_be_bytes()); o += 4;
    }

    frame[54 + opts_len..54 + opts_len + payload.len()].copy_from_slice(payload);

    let tcp_cksum = tcp_checksum(src_ip, dst_ip, &frame[34..total]);
    frame[50..52].copy_from_slice(&tcp_cksum.to_be_bytes());

    frame
}

// ── UDP builder ───────────────────────────────────────────────────────────────

/// Build a minimal Ethernet+IPv4+UDP frame with valid checksums.
pub fn build_udp_data(
    src_mac:  [u8; 6],
    dst_mac:  [u8; 6],
    src_ip:   [u8; 4],
    dst_ip:   [u8; 4],
    src_port: u16,
    dst_port: u16,
    payload:  &[u8],
) -> Vec<u8> {
    let udp_len = 8usize + payload.len();
    let ip_len  = 20 + udp_len;
    let total   = 14 + ip_len;
    let mut frame = vec![0u8; total];

    frame[0..6].copy_from_slice(&dst_mac);
    frame[6..12].copy_from_slice(&src_mac);
    frame[12..14].copy_from_slice(&[0x08, 0x00]);

    frame[14] = 0x45;
    frame[15] = 0x00;
    frame[16..18].copy_from_slice(&(ip_len as u16).to_be_bytes());
    frame[18..20].copy_from_slice(&[0x00, 0x00]);
    frame[20..22].copy_from_slice(&[0x40, 0x00]);
    frame[22] = 64;
    frame[23] = 17;
    frame[26..30].copy_from_slice(&src_ip);
    frame[30..34].copy_from_slice(&dst_ip);
    let ip_cksum = internet_checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&ip_cksum.to_be_bytes());

    frame[34..36].copy_from_slice(&src_port.to_be_bytes());
    frame[36..38].copy_from_slice(&dst_port.to_be_bytes());
    frame[38..40].copy_from_slice(&(udp_len as u16).to_be_bytes());
    frame[42..42 + payload.len()].copy_from_slice(payload);

    let udp_cksum = udp_checksum(src_ip, dst_ip, &frame[34..total]);
    frame[40..42].copy_from_slice(&udp_cksum.to_be_bytes());

    frame
}

// ── ICMP builders ─────────────────────────────────────────────────────────────

/// Build an ICMP message frame with arbitrary type, code, and embedded original header.
pub fn build_icmp_generic(
    src_mac:     [u8; 6],
    dst_mac:     [u8; 6],
    icmp_src_ip: [u8; 4],
    icmp_dst_ip: [u8; 4],
    icmp_type:   u8,
    icmp_code:   u8,
    extra_bytes: [u8; 4],
    orig_frame:  &[u8],
) -> Vec<u8> {
    let embedded = {
        let start = 14usize;
        let end   = (start + 28).min(orig_frame.len());
        &orig_frame[start..end]
    };
    let embedded_len = embedded.len();
    let icmp_payload_len = 8 + embedded_len;
    let ip_len  = 20 + icmp_payload_len;
    let total   = 14 + ip_len;
    let mut frame = vec![0u8; total];

    frame[0..6].copy_from_slice(&dst_mac);
    frame[6..12].copy_from_slice(&src_mac);
    frame[12..14].copy_from_slice(&[0x08, 0x00]);

    frame[14] = 0x45;
    frame[16..18].copy_from_slice(&(ip_len as u16).to_be_bytes());
    frame[20..22].copy_from_slice(&[0x00, 0x00]);
    frame[22] = 64; frame[23] = 1;
    frame[26..30].copy_from_slice(&icmp_src_ip);
    frame[30..34].copy_from_slice(&icmp_dst_ip);
    let ip_cksum = internet_checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&ip_cksum.to_be_bytes());

    let icmp_start = 34;
    frame[icmp_start]     = icmp_type;
    frame[icmp_start + 1] = icmp_code;
    frame[icmp_start + 4..icmp_start + 8].copy_from_slice(&extra_bytes);

    let embed_start = icmp_start + 8;
    frame[embed_start..embed_start + embedded_len].copy_from_slice(embedded);

    let icmp_cksum = internet_checksum(&frame[icmp_start..icmp_start + icmp_payload_len]);
    frame[icmp_start + 2..icmp_start + 4].copy_from_slice(&icmp_cksum.to_be_bytes());

    frame
}

/// Build an Ethernet+IPv4+ICMP "Fragmentation Needed" (type=3, code=4) frame.
pub fn build_icmp_frag_needed(
    src_mac:      [u8; 6],
    dst_mac:      [u8; 6],
    icmp_src_ip:  [u8; 4],
    icmp_dst_ip:  [u8; 4],
    next_hop_mtu: u16,
    orig_frame:   &[u8],
) -> Vec<u8> {
    let embedded = {
        let start = 14usize;
        let end   = (start + 28).min(orig_frame.len());
        &orig_frame[start..end]
    };
    let embedded_len = embedded.len();

    let icmp_payload_len = 8 + embedded_len;
    let ip_len  = 20 + icmp_payload_len;
    let total   = 14 + ip_len;
    let mut frame = vec![0u8; total];

    frame[0..6].copy_from_slice(&dst_mac);
    frame[6..12].copy_from_slice(&src_mac);
    frame[12..14].copy_from_slice(&[0x08, 0x00]);

    frame[14] = 0x45;
    frame[16..18].copy_from_slice(&(ip_len as u16).to_be_bytes());
    frame[20..22].copy_from_slice(&[0x00, 0x00]);
    frame[22] = 64; frame[23] = 1;
    frame[26..30].copy_from_slice(&icmp_src_ip);
    frame[30..34].copy_from_slice(&icmp_dst_ip);
    let ip_cksum = internet_checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&ip_cksum.to_be_bytes());

    let icmp_start = 34;
    frame[icmp_start]     = 3;
    frame[icmp_start + 1] = 4;
    frame[icmp_start + 2] = 0;
    frame[icmp_start + 3] = 0;
    frame[icmp_start + 4] = 0;
    frame[icmp_start + 5] = 0;
    frame[icmp_start + 6..icmp_start + 8].copy_from_slice(&next_hop_mtu.to_be_bytes());

    let embed_start = icmp_start + 8;
    frame[embed_start..embed_start + embedded_len].copy_from_slice(embedded);

    let icmp_cksum = internet_checksum(&frame[icmp_start..icmp_start + icmp_payload_len]);
    frame[icmp_start + 2..icmp_start + 4].copy_from_slice(&icmp_cksum.to_be_bytes());

    frame
}
