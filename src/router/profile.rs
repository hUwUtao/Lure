use std::sync::Arc;

use net::Uuid;
use serde::{Deserialize, Serialize, ser::SerializeStruct};

#[derive(Debug, Clone)]
pub struct Profile {
    pub name: Arc<str>,
    pub uuid: Option<Uuid>,
}

#[derive(Deserialize)]
struct ProfileWire {
    name: String,
    uuid: Option<String>,
}

impl<'de> Deserialize<'de> for Profile {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let state = ProfileWire::deserialize(deserializer)?;
        Ok(Profile {
            name: Arc::from(state.name),
            uuid: match state.uuid {
                Some(value) => Some(parse_uuid(&value).map_err(serde::de::Error::custom)?),
                None => None,
            },
        })
    }
}

impl Serialize for Profile {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("Profile", 2)?;
        state.serialize_field("name", self.name.as_ref())?;
        state.serialize_field("uuid", &self.uuid.map(|v| v.to_string()))?;
        state.end()
    }
}

fn parse_uuid(value: &str) -> Result<Uuid, &'static str> {
    let mut nibbles = Vec::with_capacity(32);
    for ch in value.chars() {
        if ch == '-' {
            continue;
        }
        let nibble = match ch {
            '0'..='9' => ch as u8 - b'0',
            'a'..='f' => 10 + (ch as u8 - b'a'),
            'A'..='F' => 10 + (ch as u8 - b'A'),
            _ => return Err("invalid uuid character"),
        };
        nibbles.push(nibble);
    }

    if nibbles.len() != 32 {
        return Err("invalid uuid length");
    }

    let mut bytes = [0u8; 16];
    for i in 0..16 {
        bytes[i] = (nibbles[2 * i] << 4) | nibbles[2 * i + 1];
    }

    Ok(Uuid::from_bytes(bytes))
}
