use serde::{Deserialize, Serialize};

/// Signature result returned by backend signer / daemon.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Signature {
    /// Signature bytes in ECDSA ASN.1 DER (`X9.62`) encoding.
    pub bytes: Vec<u8>,
    /// Optional 32-byte `r` scalar as `0x`-prefixed hex.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r_hex: Option<String>,
    /// Optional 32-byte `s` scalar as `0x`-prefixed hex.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub s_hex: Option<String>,
    /// Optional ECDSA `v` value (`0`/`1` for typed txs).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub v: Option<u64>,
    /// Optional signed raw transaction bytes as `0x`-prefixed hex.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_tx_hex: Option<String>,
    /// Optional transaction hash as `0x`-prefixed hex.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_hash_hex: Option<String>,
}

impl Signature {
    /// Constructs a signature response from DER bytes.
    #[must_use]
    pub fn from_der(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            ..Self::default()
        }
    }
}
