use base64::prelude::*;
use rand::RngCore;

pub fn mint_run_id() -> String {
    let mut bytes = [0_u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    BASE64_URL_SAFE_NO_PAD.encode(bytes)
}

pub fn short_run_id(run_id: &str) -> &str {
    run_id.get(..8).unwrap_or(run_id)
}
