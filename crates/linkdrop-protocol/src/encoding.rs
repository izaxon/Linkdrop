use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use url::{Host, Url};

use crate::error::{ProtocolError, Result};

pub fn encode_base64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn decode_base64url(value: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(value).map_err(ProtocolError::from)
}

pub fn tagged_base64(prefix: &str, bytes: &[u8]) -> String {
    format!("{prefix}:{}", encode_base64url(bytes))
}

pub fn parse_tagged_base64(value: &str, expected_prefix: &str) -> Result<Vec<u8>> {
    let (prefix, raw) = value.split_once(':').ok_or_else(|| {
        ProtocolError::Validation(format!("expected {expected_prefix}:<base64url>"))
    })?;
    if prefix != expected_prefix {
        return Err(ProtocolError::Validation(format!(
            "expected key prefix {expected_prefix}, found {prefix}"
        )));
    }
    decode_base64url(raw)
}

pub fn validate_server_url(server: &str, allow_http_local: bool) -> Result<Url> {
    let url = Url::parse(server)?;
    match url.scheme() {
        "https" => {}
        "http" if allow_http_local && is_local_host(&url) => {}
        other => {
            return Err(ProtocolError::Validation(format!(
                "server URL must use https, or http for localhost development only (got {other})"
            )));
        }
    }

    if url.host().is_none() {
        return Err(ProtocolError::Validation(
            "server URL must include a host".to_string(),
        ));
    }

    Ok(url)
}

fn is_local_host(url: &Url) -> bool {
    match url.host() {
        Some(Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(addr)) => addr.is_loopback(),
        Some(Host::Ipv6(addr)) => addr.is_loopback(),
        None => false,
    }
}
