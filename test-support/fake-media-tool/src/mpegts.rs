pub(crate) const PACKET_SIZE: usize = 188;

const PAT_PID: u16 = 0x0000;
const PMT_PID: u16 = 0x0100;
const VIDEO_PID: u16 = 0x0101;

pub(crate) fn valid_segment() -> &'static [u8] {
    &VALID_SEGMENT
}

pub(crate) fn partial_segment() -> &'static [u8] {
    &VALID_SEGMENT[..PACKET_SIZE + 47]
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

const fn pes_payload() -> [u8; 36] {
    [
        0x00, 0x00, 0x01, 0xe0, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0x09, 0x10, 0x00,
        0x00, 0x01, 0x67, 0x42, 0xc0, 0x1e, 0xda, 0x01, 0xe0, 0x08, 0x9f, 0x97, 0x01, 0x6e, 0x40,
        0x00, 0x00, 0x01, 0x68, 0xce, 0x3c,
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
    fn truncation_is_distinguishable_from_valid_segment() {
        let truncated = partial_segment();

        assert_ne!(truncated.len() % PACKET_SIZE, 0);
        assert!(!has_sync_cadence(truncated));
        assert!(has_sync_cadence(valid_segment()));
    }

    fn has_sync_cadence(bytes: &[u8]) -> bool {
        !bytes.is_empty()
            && bytes.len() % PACKET_SIZE == 0
            && bytes.chunks(PACKET_SIZE).all(|packet| packet[0] == 0x47)
    }

    fn pid_at(bytes: &[u8], packet_index: usize) -> u16 {
        let offset = packet_index * PACKET_SIZE;
        (((bytes[offset + 1] & 0x1f) as u16) << 8) | bytes[offset + 2] as u16
    }
}
