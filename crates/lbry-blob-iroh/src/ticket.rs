//! Pasteable superpeer tickets (JSON EndpointAddr, base64url).

use anyhow::{Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use iroh::EndpointAddr;

pub fn encode_ticket(addr: &EndpointAddr) -> Result<String> {
    let json = serde_json::to_vec(addr).context("serialize EndpointAddr")?;
    Ok(URL_SAFE_NO_PAD.encode(json))
}

pub fn decode_ticket(ticket: &str) -> Result<EndpointAddr> {
    let raw = URL_SAFE_NO_PAD
        .decode(ticket.trim())
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(ticket.trim()))
        .context("base64 ticket")?;
    serde_json::from_slice(&raw).context("parse EndpointAddr JSON")
}
