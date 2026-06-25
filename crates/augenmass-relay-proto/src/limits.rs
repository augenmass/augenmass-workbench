pub const PROTOCOL_OVERHEAD_BYTES: usize = 16 * 1024;
pub const WS_MESSAGE_HARD_CAP: usize = 2 * 1024 * 1024;

pub fn ws_message_limit(max_body_bytes: usize) -> usize {
    let encoded = max_body_bytes.saturating_mul(4).div_ceil(3);
    encoded
        .saturating_add(PROTOCOL_OVERHEAD_BYTES)
        .min(WS_MESSAGE_HARD_CAP)
}

pub fn max_body_for_ws_cap() -> usize {
    WS_MESSAGE_HARD_CAP
        .saturating_sub(PROTOCOL_OVERHEAD_BYTES)
        .saturating_mul(3)
        / 4
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_body_can_fit_under_hard_cap() {
        let one_mib = 1024 * 1024;
        assert!(ws_message_limit(one_mib) < WS_MESSAGE_HARD_CAP);
        assert!(max_body_for_ws_cap() > one_mib);
    }

    #[test]
    fn configured_limit_is_clamped_to_hard_cap() {
        assert_eq!(ws_message_limit(usize::MAX), WS_MESSAGE_HARD_CAP);
    }
}
