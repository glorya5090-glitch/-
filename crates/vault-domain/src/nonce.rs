use std::fmt;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

/// Agent request for reserving a unique broadcast nonce.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NonceReservationRequest {
    /// Client-generated unique request identifier for replay protection.
    pub request_id: Uuid,
    /// Agent key used for authorization.
    pub agent_key_id: Uuid,
    /// Bearer token bound to `agent_key_id`.
    #[serde(with = "crate::serde_helpers::zeroizing_string")]
    pub agent_auth_token: Zeroizing<String>,
    /// EVM chain id for nonce scope.
    pub chain_id: u64,
    /// Minimum nonce the caller is willing to reserve.
    pub min_nonce: u64,
    /// When true, reserve exactly `min_nonce` instead of allowing a higher nonce head.
    #[serde(default)]
    pub exact_nonce: bool,
    /// Request timestamp.
    pub requested_at: OffsetDateTime,
    /// Request expiry timestamp.
    pub expires_at: OffsetDateTime,
}

impl fmt::Debug for NonceReservationRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NonceReservationRequest")
            .field("request_id", &self.request_id)
            .field("agent_key_id", &self.agent_key_id)
            .field("agent_auth_token", &"<redacted>")
            .field("chain_id", &self.chain_id)
            .field("min_nonce", &self.min_nonce)
            .field("exact_nonce", &self.exact_nonce)
            .field("requested_at", &self.requested_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl NonceReservationRequest {
    pub fn zeroize_secrets(&mut self) {
        self.agent_auth_token.zeroize();
    }
}

/// Reserved nonce lease for a specific agent and chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NonceReservation {
    /// Unique reservation identifier.
    pub reservation_id: Uuid,
    /// Agent key that owns this reservation.
    pub agent_key_id: Uuid,
    /// Backing vault key used for signing scope.
    pub vault_key_id: Uuid,
    /// EVM chain id for nonce scope.
    pub chain_id: u64,
    /// Reserved nonce value.
    pub nonce: u64,
    /// Lease issuance timestamp.
    pub issued_at: OffsetDateTime,
    /// Lease expiry timestamp.
    pub expires_at: OffsetDateTime,
}

impl NonceReservation {
    /// Returns whether the reservation is currently active at `now`.
    #[must_use]
    pub fn is_valid_at(&self, now: OffsetDateTime) -> bool {
        now >= self.issued_at && now < self.expires_at
    }
}

/// Agent request for explicitly releasing a nonce reservation.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NonceReleaseRequest {
    /// Client-generated unique request identifier for replay protection.
    pub request_id: Uuid,
    /// Agent key used for authorization.
    pub agent_key_id: Uuid,
    /// Bearer token bound to `agent_key_id`.
    #[serde(with = "crate::serde_helpers::zeroizing_string")]
    pub agent_auth_token: Zeroizing<String>,
    /// Reservation id to release.
    pub reservation_id: Uuid,
    /// Request timestamp.
    pub requested_at: OffsetDateTime,
    /// Request expiry timestamp.
    pub expires_at: OffsetDateTime,
}

impl fmt::Debug for NonceReleaseRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NonceReleaseRequest")
            .field("request_id", &self.request_id)
            .field("agent_key_id", &self.agent_key_id)
            .field("agent_auth_token", &"<redacted>")
            .field("reservation_id", &self.reservation_id)
            .field("requested_at", &self.requested_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl NonceReleaseRequest {
    pub fn zeroize_secrets(&mut self) {
        self.agent_auth_token.zeroize();
    }
}
