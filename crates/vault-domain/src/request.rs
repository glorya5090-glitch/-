use std::fmt;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::AgentAction;

/// Request sent by an agent to receive signature approval.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignRequest {
    /// Client-generated unique request identifier for replay protection.
    pub request_id: Uuid,
    /// Agent key used for authorization.
    pub agent_key_id: Uuid,
    /// Bearer token bound to `agent_key_id`.
    #[serde(with = "crate::serde_helpers::zeroizing_string")]
    pub agent_auth_token: Zeroizing<String>,
    /// Payload to sign.
    ///
    /// Security contract: payload must be the canonical
    /// `serde_json::to_vec(&action)` encoding of [`AgentAction`]; daemon rejects
    /// semantic or byte-level mismatches.
    pub payload: Vec<u8>,
    /// Semantic action details used by policy checks.
    pub action: AgentAction,
    /// Request timestamp.
    pub requested_at: OffsetDateTime,
    /// Request expiry timestamp.
    pub expires_at: OffsetDateTime,
}

impl fmt::Debug for SignRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignRequest")
            .field("request_id", &self.request_id)
            .field("agent_key_id", &self.agent_key_id)
            .field("agent_auth_token", &"<redacted>")
            .field("payload", &self.payload)
            .field("action", &self.action)
            .field("requested_at", &self.requested_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl SignRequest {
    pub fn zeroize_secrets(&mut self) {
        self.agent_auth_token.zeroize();
        self.payload.zeroize();
    }
}
