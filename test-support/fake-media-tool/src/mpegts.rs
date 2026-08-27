pub(crate) const PACKET_SIZE: usize = 188;

const PAT_PID: u16 = 0x0000;
const PMT_PID: u16 = 0x0100;
const VIDEO_PID: u16 = 0x0101;

pub(crate) fn valid_segment() -> &'static [u8] {
    &VALID_SEGMENT
}

pub(crate) fn partial_segment() -> &'static [u8] {
    &VALID_SEGMENT[..PACKET_SIZE * 2 + 47]
}

const VALID_SEGMENT: [u8; PACKET_SIZE * 3] = build_segment();

const fn build_segment() -> [u8; PACKET_SIZE * 3] {
    let mut segment = [0xff; PACKET_SIZE * 3];
    write_packet(&mut segment, 0, PAT_PID, true, 0, &pat_section());
    write_packet(&mut segment, 1, PMT_PID, true, 0, &pmt_section());
    write_packet(&mut segment, 2, VIDEO_PID, true, 0, &pes_payload());
    segment
}

const fn write_packet(
    segment: &mut [u8; PACKET_SIZE * 3],
    packet_index: usize,
    pid: u16,
    payload_unit_start: bool,
    continuity_counter: u8,
    payload: &[u8],
) {
    let offset = packet_index * PACKET_SIZE;
    segment[offset] = 0x47;
    segment[offset + 1] =
        ((if payload_unit_start { 0x40 } else { 0x00 }) | ((pid >> 8) as u8)) & 0x5f;
    segment[offset + 2] = pid as u8;
    segment[offset + 3] = 0x10 | (continuity_counter & 0x0f);

    let mut index = 0;
    while index < payload.len() {
        segment[offset + 4 + index] = payload[index];
        index += 1;
    }
}

const fn pat_section() -> [u8; 17] {
    let mut section = [
        0x00, 0x00, 0xb0, 0x0d, 0x00, 0x01, 0xc1, 0x00, 0x00, 0x00, 0x01, 0xe1, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ];
    let crc = crc32_mpeg(&section, 1, 12);
    section[13] = (crc >> 24) as u8;
    section[14] = (crc >> 16) as u8;
    section[15] = (crc >> 8) as u8;
    section[16] = crc as u8;
    section
}

const fn pmt_section() -> [u8; 22] {
    let mut section = [
        0x00, 0x02, 0xb0, 0x12, 0x00, 0x01, 0xc1, 0x00, 0x00, 0xe1, 0x01, 0xf0, 0x00, 0x1b, 0xe1,
        0x01, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let crc = crc32_mpeg(&section, 1, 17);
    section[18] = (crc >> 24) as u8;
    section[19] = (crc >> 16) as u8;
    section[20] = (crc >> 8) as u8;
    section[21] = crc as u8;
    section
}

const fn pes_payload() -> [u8; 53] {
    [
        // PES header: finite packet length and PTS-only timestamp at 90_000 ticks (one second).
        0x00, 0x00, 0x01, 0xe0, 0x00, 0x2f, 0x80, 0x80, 0x05, 0x21, 0x00, 0x05, 0xbf, 0x21,
        // One Annex-B access unit: AUD, baseline SPS, PPS, and an IDR VCL slice.
        0x00, 0x00, 0x01, 0x09, 0xf0, 0x00, 0x00, 0x01, 0x67, 0x42, 0xc0, 0x1e, 0xda, 0x01, 0xe0,
        0x08, 0x9f, 0x97, 0x01, 0x6e, 0x40, 0x00, 0x00, 0x01, 0x68, 0xce, 0x3c, 0x80, 0x00, 0x00,
        0x01, 0x65, 0x88, 0x84, 0x00, 0x0a, 0xf2, 0x62, 0x80,
    ]
}

const fn crc32_mpeg(bytes: &[u8], start: usize, len: usize) -> u32 {
    let mut crc = 0xffff_ffff;
    let mut index = start;
    while index < start + len {
        crc ^= (bytes[index] as u32) << 24;
        let mut bit = 0;
        while bit < 8 {
            if (crc & 0x8000_0000) != 0 {
                crc = (crc << 1) ^ 0x04c1_1db7;
            } else {
                crc <<= 1;
            }
            bit += 1;
        }
        index += 1;
    }
    crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_segment_has_packet_sync_cadence_and_expected_pids() {
        let segment = valid_segment();

        assert_eq!(segment.len(), PACKET_SIZE * 3);
        assert!(has_sync_cadence(segment));
        assert_eq!(pid_at(segment, 0), PAT_PID);
        assert_eq!(pid_at(segment, 1), PMT_PID);
        assert_eq!(pid_at(segment, 2), VIDEO_PID);
    }

    #[test]
    fn valid_segment_contains_pat_pmt_and_pes_structures() {
        let segment = valid_segment();

        assert_eq!(segment[4], 0x00);
        assert_eq!(segment[5], 0x00);
        assert_eq!(segment[PACKET_SIZE + 4], 0x00);
        assert_eq!(segment[PACKET_SIZE + 5], 0x02);
        assert_eq!(
            &segment[(PACKET_SIZE * 2 + 4)..(PACKET_SIZE * 2 + 8)],
            [0x00, 0x00, 0x01, 0xe0]
        );
    }

    #[test]
    fn independent_parser_finds_timestamped_idr_access_unit() {
        let segment = valid_segment();
        let packet = &segment[(PACKET_SIZE * 2)..(PACKET_SIZE * 3)];
        let payload = &packet[4..];

        assert_eq!(&payload[..4], [0x00, 0x00, 0x01, 0xe0]);
        let pes_packet_length = u16::from_be_bytes([payload[4], payload[5]]) as usize;
        assert!(pes_packet_length > 8);
        assert_eq!(payload[7] & 0x80, 0x80, "PTS flag must be present");
        assert_eq!(payload[8], 5, "PTS must use the five-byte PES form");
        assert_eq!(decode_pts(&payload[9..14]), 90_000);

        let elementary_length = pes_packet_length - 3 - payload[8] as usize;
        let elementary = &payload[14..14 + elementary_length];
        let nal_types = annex_b_nal_types(elementary);
        assert_eq!(nal_types, vec![9, 7, 8, 5]);
        assert!(
            elementary
                .windows(4)
                .any(|window| window == [0x00, 0x00, 0x01, 0x65]),
            "access unit must contain an IDR VCL NAL"
        );
    }

    #[test]
    fn truncation_is_distinguishable_from_valid_segment() {
        let truncated = partial_segment();

        assert_ne!(truncated.len() % PACKET_SIZE, 0);
        assert!(!has_sync_cadence(truncated));
        assert!(has_sync_cadence(valid_segment()));
        assert!(truncated.len() > PACKET_SIZE * 2);
        assert_eq!(truncated[PACKET_SIZE * 2], 0x47);
    }

    fn has_sync_cadence(bytes: &[u8]) -> bool {
        !bytes.is_empty()
            && bytes.len().is_multiple_of(PACKET_SIZE)
            && bytes.chunks(PACKET_SIZE).all(|packet| packet[0] == 0x47)
    }

    fn pid_at(bytes: &[u8], packet_index: usize) -> u16 {
        let offset = packet_index * PACKET_SIZE;
        (((bytes[offset + 1] & 0x1f) as u16) << 8) | bytes[offset + 2] as u16
    }

    fn decode_pts(bytes: &[u8]) -> u64 {
        assert_eq!(bytes.len(), 5);
        (((bytes[0] as u64 >> 1) & 0x07) << 30)
            | ((bytes[1] as u64) << 22)
            | (((bytes[2] as u64 >> 1) & 0x7f) << 15)
            | ((bytes[3] as u64) << 7)
            | ((bytes[4] as u64 >> 1) & 0x7f)
    }

    fn annex_b_nal_types(bytes: &[u8]) -> Vec<u8> {
        let mut types = Vec::new();
        let mut offset = 0;
        while offset + 4 <= bytes.len() {
            if bytes[offset..].starts_with(&[0x00, 0x00, 0x01]) {
                types.push(bytes[offset + 3] & 0x1f);
                offset += 4;
            } else if bytes[offset..].starts_with(&[0x00, 0x00, 0x00, 0x01]) {
                types.push(bytes[offset + 4] & 0x1f);
                offset += 5;
            } else {
                offset += 1;
            }
        }
        types
    }
}
