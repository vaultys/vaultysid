//! Service identities and service anchors (`rfc/SERVICE-IDENTITIES.md`): one
//! unlinkable VaultysID per service, derived from a master secret, and the
//! signed identity a service publishes under its web origin.
//!
//! Byte-compatible with the TypeScript reference (`typescript/src/serviceIdentity.ts`,
//! `typescript/src/serviceAnchor.ts`); checked against its vectors in
//! `tests/service_identity_vectors.rs`.

use crate::crypto::hash;
use crate::error::{Error, Result};
use crate::vaultys_id::{Algorithm, VaultysId};
use hkdf::Hkdf;
use sha2::Sha256;
use std::net::Ipv6Addr;
use zeroize::Zeroize;

/// HKDF salt of a service identity (RFC §4).
pub const SERVICE_IDENTITY_SALT: &str = "vaultysid/service-identity/v1";
/// Length of the master secret, in bytes.
pub const MASTER_SECRET_LENGTH: usize = 32;
/// Longest accepted service id input.
pub const MAX_SERVICE_ID_INPUT_LENGTH: usize = 300;
/// Domain-separation label of a service anchor signature (RFC §8).
pub const SERVICE_ANCHOR_LABEL: &str = "vaultysid/service-anchor/v1";
/// Where a service serves its anchor, under its origin.
pub const SERVICE_ANCHOR_PATH: &str = "/.well-known/vaultysid-service";

const DERIVATION_VERSION: &str = "v1";
const RAW_INCIPIT: &[u8] = b"VAULTYS_RAW";
const ANCHOR_HEADER: [u8; 2] = [0x01, 0x01];
const MAX_ANCHOR_SERVICE_ID: usize = 300;
const MAX_ANCHOR_ID: usize = 8192;

fn invalid() -> Error {
    Error::InvalidKeyFormat("invalid service id".into())
}

fn is_label(label: &str) -> bool {
    let b = label.as_bytes();
    if b.is_empty() || b.len() > 63 {
        return false;
    }
    let ok = |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-';
    if !b.iter().all(|&c| ok(c)) || b[0] == b'-' || b[b.len() - 1] == b'-' {
        return false;
    }
    !(b.len() >= 4 && &b[2..4] == b"--" && !label.starts_with("xn--"))
}

fn is_dns_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 253 {
        return false;
    }
    let labels: Vec<&str> = name.split('.').collect();
    labels.len() >= 2 && labels.iter().all(|l| is_label(l))
}

fn ends_in_number(host: &str) -> bool {
    let last = host.rsplit('.').next().unwrap_or("");
    (!last.is_empty() && last.bytes().all(|c| c.is_ascii_digit()))
        || (last.starts_with("0x") && last[2..].bytes().all(|c| c.is_ascii_hexdigit()))
}

fn is_canonical_ipv4(host: &str) -> bool {
    let parts: Vec<&str> = host.split('.').collect();
    parts.len() == 4
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.len() <= 3
                && p.bytes().all(|c| c.is_ascii_digit())
                && (p.len() == 1 || !p.starts_with('0'))
                && p.parse::<u16>().map(|n| n <= 255).unwrap_or(false)
        })
}

fn canonical_port(scheme: &str, port: Option<&str>) -> Result<String> {
    let Some(port) = port else {
        return Ok(String::new());
    };
    let b = port.as_bytes();
    if b.is_empty() || b.len() > 5 || b[0] == b'0' || !b.iter().all(|c| c.is_ascii_digit()) {
        return Err(invalid());
    }
    if port.parse::<u32>().map(|n| n > 65535).unwrap_or(true) {
        return Err(invalid());
    }
    let default = if scheme == "https" { "443" } else { "80" };
    Ok(if port == default {
        String::new()
    } else {
        format!(":{port}")
    })
}

/// Decodes a Punycode label body (RFC 3492 §6.2) only to refuse labels that cannot
/// be decoded, as the WHATWG parser of the TypeScript reference does. The decoded
/// form is never output.
fn punycode_decodes(input: &str) -> bool {
    const BASE: u32 = 36;
    const T_MIN: u32 = 1;
    const T_MAX: u32 = 26;
    const SKEW: u32 = 38;
    const DAMP: u32 = 700;
    let adapt = |mut delta: u32, num_points: u32, first: bool| -> u32 {
        delta /= if first { DAMP } else { 2 };
        delta += delta / num_points;
        let mut k = 0;
        while delta > ((BASE - T_MIN) * T_MAX) / 2 {
            delta /= BASE - T_MIN;
            k += BASE;
        }
        k + (BASE - T_MIN + 1) * delta / (delta + SKEW)
    };
    let digit = |c: u8| -> Option<u32> {
        match c {
            b'0'..=b'9' => Some((c - b'0') as u32 + 26),
            b'a'..=b'z' => Some((c - b'a') as u32),
            b'A'..=b'Z' => Some((c - b'A') as u32),
            _ => None,
        }
    };
    let bytes = input.as_bytes();
    let (mut out_len, rest): (u32, &[u8]) = match bytes.iter().rposition(|&c| c == b'-') {
        Some(0) => (0, &bytes[1..]),
        Some(p) => (p as u32, &bytes[p + 1..]),
        None => (0, bytes),
    };
    if rest.is_empty() {
        return false;
    }
    let (mut n, mut i, mut bias): (u32, u32, u32) = (128, 0, 72);
    let mut pos = 0;
    while pos < rest.len() {
        let old_i = i;
        let mut w: u32 = 1;
        let mut k = BASE;
        loop {
            if pos >= rest.len() {
                return false;
            }
            let Some(d) = digit(rest[pos]) else {
                return false;
            };
            pos += 1;
            let Some(dw) = d.checked_mul(w) else {
                return false;
            };
            let Some(ni) = i.checked_add(dw) else {
                return false;
            };
            i = ni;
            let t = if k <= bias {
                T_MIN
            } else if k >= bias + T_MAX {
                T_MAX
            } else {
                k - bias
            };
            if d < t {
                break;
            }
            let Some(nw) = w.checked_mul(BASE - t) else {
                return false;
            };
            w = nw;
            k += BASE;
        }
        bias = adapt(i - old_i, out_len + 1, old_i == 0);
        let Some(nn) = n.checked_add(i / (out_len + 1)) else {
            return false;
        };
        n = nn;
        i %= out_len + 1;
        if n < 0x80 || char::from_u32(n).is_none() {
            return false;
        }
        out_len += 1;
        i += 1;
    }
    true
}

/// Canonical identifier of a service (RFC §3). Errors on anything refused.
pub fn canonical_service_id(input: &str, allow_development_hosts: bool) -> Result<String> {
    if input.is_empty() || input.len() > MAX_SERVICE_ID_INPUT_LENGTH {
        return Err(invalid());
    }
    if !input.bytes().all(|c| (0x21..=0x7e).contains(&c))
        || input.bytes().any(|c| b"%\\@?#".contains(&c))
    {
        return Err(invalid());
    }
    if let Some(name) = input.strip_prefix("app:") {
        return if is_dns_name(name) {
            Ok(input.to_string())
        } else {
            Err(invalid())
        };
    }
    let lower = input.to_ascii_lowercase();
    let (scheme, rest) = if let Some(r) = lower.strip_prefix("https://") {
        ("https", &input[8..8 + r.len()])
    } else if let Some(r) = lower.strip_prefix("http://") {
        ("http", &input[7..7 + r.len()])
    } else {
        return Err(invalid());
    };
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    if rest.contains('/') {
        return Err(invalid());
    }
    // IPv6 literal (development only), in the exact form WHATWG serializes
    if rest.starts_with('[') {
        if !allow_development_hosts {
            return Err(invalid());
        }
        let close = rest.find(']').ok_or_else(invalid)?;
        let host = rest[..=close].to_ascii_lowercase();
        let after = &rest[close + 1..];
        let port = match after {
            "" => None,
            p if p.starts_with(':') => Some(&p[1..]),
            _ => return Err(invalid()),
        };
        let inner = &host[1..host.len() - 1];
        if inner.contains('.') {
            return Err(invalid());
        }
        let addr: Ipv6Addr = inner.parse().map_err(|_| invalid())?;
        if format!("[{addr}]") != host {
            return Err(invalid());
        }
        return Ok(format!(
            "{scheme}://{host}{}",
            canonical_port(scheme, port)?
        ));
    }
    let (host, port) = match rest.find(':') {
        Some(p) => (&rest[..p], Some(&rest[p + 1..])),
        None => (rest, None),
    };
    if host.contains(['[', ']']) {
        return Err(invalid());
    }
    let host = host.to_ascii_lowercase();
    let development = if is_canonical_ipv4(&host) || host == "localhost" {
        true
    } else if is_dns_name(&host) && !ends_in_number(&host) {
        if host
            .split('.')
            .any(|l| l.starts_with("xn--") && !punycode_decodes(&l[4..]))
        {
            return Err(invalid());
        }
        host.ends_with(".localhost")
    } else {
        return Err(invalid());
    };
    if (development || scheme == "http") && !allow_development_hosts {
        return Err(invalid());
    }
    Ok(format!(
        "{scheme}://{host}{}",
        canonical_port(scheme, port)?
    ))
}

/// True if `service_id` is already canonical.
pub fn is_canonical_service_id(service_id: &str, allow_development_hosts: bool) -> bool {
    canonical_service_id(service_id, allow_development_hosts)
        .map(|c| c == service_id)
        .unwrap_or(false)
}

fn lp(bytes: &[u8]) -> Vec<u8> {
    let mut out = (bytes.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(bytes);
    out
}

/// Signature algorithm of a service identity, as named in the HKDF info.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceAlgorithm {
    Ed25519,
    Dilithium,
    /// Hybrid Ed25519 + ML-DSA-87: entropy only, the Rust crate has no hybrid key manager yet.
    DilithiumEd25519,
}

impl ServiceAlgorithm {
    pub fn name(self) -> &'static str {
        match self {
            Self::Ed25519 => "ed25519",
            Self::Dilithium => "dilithium",
            Self::DilithiumEd25519 => "dilithium_ed25519",
        }
    }
}

/// Role of a service identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceRole {
    Machine,
    Person,
    Organization,
}

impl ServiceRole {
    pub fn name(self) -> &'static str {
        match self {
            Self::Machine => "machine",
            Self::Person => "person",
            Self::Organization => "organization",
        }
    }
    fn type_byte(self) -> u8 {
        match self {
            Self::Machine => 0,
            Self::Person => 1,
            Self::Organization => 2,
        }
    }
}

/// HKDF info: lp("v1") || lp(alg) || lp(type name) || lp(canonical).
pub fn service_identity_info(
    alg: ServiceAlgorithm,
    role: ServiceRole,
    post_quantum: bool,
    canonical: &str,
) -> Vec<u8> {
    let type_name = if post_quantum {
        format!("{}-pq", role.name())
    } else {
        role.name().to_string()
    };
    let mut out = lp(DERIVATION_VERSION.as_bytes());
    out.extend(lp(alg.name().as_bytes()));
    out.extend(lp(type_name.as_bytes()));
    out.extend(lp(canonical.as_bytes()));
    out
}

/// Secret entropy of a service identity (RFC §4). The caller must zeroize it.
pub fn derive_service_entropy(
    master: &[u8],
    service_id: &str,
    alg: ServiceAlgorithm,
    role: ServiceRole,
    post_quantum: bool,
) -> Result<Vec<u8>> {
    if master.len() != MASTER_SECRET_LENGTH || master.iter().all(|&b| b == 0) {
        return Err(Error::InvalidKeyFormat("invalid master secret".into()));
    }
    if post_quantum && alg == ServiceAlgorithm::Ed25519 {
        return Err(Error::InvalidKeyFormat(
            "post-quantum identities require a dilithium or dilithium_ed25519 key manager".into(),
        ));
    }
    let canonical = canonical_service_id(service_id, false)?;
    let hk = Hkdf::<Sha256>::new(Some(SERVICE_IDENTITY_SALT.as_bytes()), master);
    let mut out = vec![0u8; 32];
    hk.expand(
        &service_identity_info(alg, role, post_quantum, &canonical),
        &mut out,
    )
    .map_err(|_| Error::KeyDerivationFailed("hkdf".into()))?;
    Ok(out)
}

/// Derives the classical VaultysID of `service_id` from `master` (Ed25519 or Dilithium).
pub async fn derive_service_identity(
    master: &[u8],
    service_id: &str,
    alg: ServiceAlgorithm,
    role: ServiceRole,
) -> Result<VaultysId> {
    let algorithm = match alg {
        ServiceAlgorithm::Ed25519 => Algorithm::Ed25519,
        ServiceAlgorithm::Dilithium => Algorithm::Dilithium,
        ServiceAlgorithm::DilithiumEd25519 => {
            return Err(Error::NotImplemented("hybrid service identities".into()))
        }
    };
    let mut entropy = derive_service_entropy(master, service_id, alg, role, false)?;
    let id = VaultysId::from_entropy_with_alg(&entropy, role.type_byte(), algorithm).await;
    entropy.zeroize();
    id
}

/* ------------------------------------------------------------------ anchors */

fn raw_digest(data: &[u8]) -> Vec<u8> {
    let mut b = RAW_INCIPIT.to_vec();
    b.extend_from_slice(data);
    hash("sha256", &b)
}

/// Bytes a service signs for its anchor.
pub fn service_anchor_signed_data(service_id: &str, id: &[u8]) -> Vec<u8> {
    let mut out = lp(SERVICE_ANCHOR_LABEL.as_bytes());
    out.extend_from_slice(&ANCHOR_HEADER);
    out.extend(lp(service_id.as_bytes()));
    out.extend(lp(id));
    out
}

/// URL where the anchor of a web origin is served.
pub fn service_anchor_url(service_id: &str) -> Result<String> {
    let canonical = canonical_service_id(service_id, false)?;
    if canonical.starts_with("app:") {
        return Err(Error::Other(
            "an app: service id has no web origin to publish an anchor".into(),
        ));
    }
    Ok(format!("{canonical}{SERVICE_ANCHOR_PATH}"))
}

/// Anchor of `identity` for the canonical `service_id`. The signature is a
/// VAULTYS_RAW signature, as `VaultysId.sign` in TypeScript and Go.
pub fn create_service_anchor(identity: &VaultysId, service_id: &str) -> Result<Vec<u8>> {
    if !is_canonical_service_id(service_id, false) {
        return Err(invalid());
    }
    let id = identity.id();
    let sig = identity
        .sign(&raw_digest(&service_anchor_signed_data(service_id, &id)))
        .ok_or_else(|| Error::CryptoError("the identity cannot sign the anchor".into()))?;
    if sig.is_empty() || sig.len() > 0xffff {
        return Err(Error::CryptoError(
            "the identity cannot sign the anchor".into(),
        ));
    }
    let mut out = ANCHOR_HEADER.to_vec();
    out.extend(lp(service_id.as_bytes()));
    out.extend(lp(&id));
    out.extend_from_slice(&(sig.len() as u16).to_be_bytes());
    out.extend_from_slice(&sig);
    Ok(out)
}

fn read_lp(b: &[u8], offset: usize, max: usize) -> Option<(&[u8], usize)> {
    let n = u32::from_be_bytes(b.get(offset..offset + 4)?.try_into().ok()?) as usize;
    if n == 0 || n > max {
        return None;
    }
    Some((b.get(offset + 4..offset + 4 + n)?, offset + 4 + n))
}

/// Verifies an anchor fetched from the canonical origin `service_id` and returns
/// the service's public identity, or `None` on any defect.
pub fn verify_service_anchor(anchor: &[u8], service_id: &str) -> Option<VaultysId> {
    if anchor.get(..2)? != ANCHOR_HEADER {
        return None;
    }
    let (origin, next) = read_lp(anchor, 2, MAX_ANCHOR_SERVICE_ID)?;
    let (id, next) = read_lp(anchor, next, MAX_ANCHOR_ID)?;
    let sig_len = u16::from_be_bytes(anchor.get(next..next + 2)?.try_into().ok()?) as usize;
    let sig_start = next + 2;
    if sig_len == 0 || sig_start + sig_len != anchor.len() {
        return None;
    }
    if std::str::from_utf8(origin).ok()? != service_id
        || !is_canonical_service_id(service_id, false)
    {
        return None;
    }
    // the anchor holds the full serialized id (type byte included), exactly in its own encoding
    let identity = VaultysId::from_id(id, None, None).ok()?;
    if identity.id() != id {
        return None;
    }
    let digest = raw_digest(&service_anchor_signed_data(service_id, id));
    identity
        .verify(&digest, &anchor[sig_start..])
        .then_some(identity)
}
