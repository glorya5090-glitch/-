use std::collections::HashMap;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;
use zeroize::Zeroizing;

pub mod zeroizing_string {
    use super::*;

    pub fn serialize<S>(value: &Zeroizing<String>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(value.as_str())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Zeroizing<String>, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer).map(Zeroizing::new)
    }
}

pub mod zeroizing_string_map {
    use super::*;

    pub fn serialize<S>(
        values: &HashMap<Uuid, Zeroizing<String>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let plain = values
            .iter()
            .map(|(key, value)| (*key, value.as_str()))
            .collect::<HashMap<_, _>>();
        plain.serialize(serializer)
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<HashMap<Uuid, Zeroizing<String>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        HashMap::<Uuid, String>::deserialize(deserializer).map(|values| {
            values
                .into_iter()
                .map(|(key, value)| (key, Zeroizing::new(value)))
                .collect()
        })
    }
}
