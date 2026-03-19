use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

/// Scope matcher for recipients, assets, and networks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", content = "values")]
pub enum EntityScope<T: Ord> {
    /// Match all values.
    All,
    /// Match a specific set of values.
    Set(BTreeSet<T>),
}

impl<T: Ord> EntityScope<T> {
    /// Returns whether `value` is allowed by this scope.
    #[must_use]
    pub fn allows(&self, value: &T) -> bool {
        match self {
            Self::All => true,
            Self::Set(set) => set.contains(value),
        }
    }
}
