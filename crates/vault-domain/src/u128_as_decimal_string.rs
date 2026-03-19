use serde::{Deserialize, Deserializer, Serializer};

pub fn serialize<S>(value: &u128, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&value.to_string())
}

pub fn deserialize<'de, D>(deserializer: D) -> Result<u128, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    value.parse::<u128>().map_err(serde::de::Error::custom)
}

pub mod option {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &Option<u128>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(value) => serializer.serialize_some(&value.to_string()),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<u128>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Option::<String>::deserialize(deserializer)?;
        match value {
            Some(value) => value
                .parse::<u128>()
                .map(Some)
                .map_err(serde::de::Error::custom),
            None => Ok(None),
        }
    }
}
