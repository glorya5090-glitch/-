use alloy_primitives::Address;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize};

use crate::DomainError;

/// Canonical lower-case EVM address (`0x` + 40 hex chars).
///
/// Mixed-case inputs must satisfy the EIP-55 checksum.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct EvmAddress(String);

impl EvmAddress {
    /// Returns the normalized address string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[cfg(test)]
    pub(crate) fn new_unchecked(value: impl Into<String>) -> Self {
        Self(value.into())
    }
}

impl Display for EvmAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for EvmAddress {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let payload = s
            .strip_prefix("0x")
            .or_else(|| s.strip_prefix("0X"))
            .ok_or(DomainError::InvalidAddress)?;

        if payload.len() != 40 || !payload.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(DomainError::InvalidAddress);
        }

        let prefixed = format!("0x{payload}");
        if is_mixed_case_hex(payload) {
            Address::parse_checksummed(&prefixed, None).map_err(|_| DomainError::InvalidAddress)?;
        }

        Ok(Self(prefixed.to_ascii_lowercase()))
    }
}

impl<'de> Deserialize<'de> for EvmAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_str(&value).map_err(serde::de::Error::custom)
    }
}

fn is_mixed_case_hex(value: &str) -> bool {
    let has_lower = value.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = value.chars().any(|c| c.is_ascii_uppercase());

    has_lower && has_upper
}
