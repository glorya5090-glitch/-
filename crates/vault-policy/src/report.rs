use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::PolicyError;

/// Successful policy evaluation details.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyEvaluation {
    /// Policies evaluated (priority order, low to high numeric priority).
    pub evaluated_policy_ids: Vec<Uuid>,
}

/// Policy decision for an explanation report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", content = "reason", rename_all = "snake_case")]
pub enum PolicyDecision {
    /// Request satisfies all applicable policies.
    Allow,
    /// Request was denied by policy engine.
    Deny(PolicyError),
}

/// Full policy explanation report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyExplanation {
    /// Enabled policy ids attached to the agent (priority order).
    pub attached_policy_ids: Vec<Uuid>,
    /// Attached policy ids whose recipient/asset/network scope matched the action.
    pub applicable_policy_ids: Vec<Uuid>,
    /// Policy ids evaluated in order up to decision point.
    pub evaluated_policy_ids: Vec<Uuid>,
    /// Final allow/deny decision.
    pub decision: PolicyDecision,
}
