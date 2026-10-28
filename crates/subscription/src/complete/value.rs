//! JSON structure helpers. Unknown and duplicate fields are admission errors.
use super::PolicyIssue;
use serde::{
    Deserialize, Deserializer,
    de::{Error, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Map, Value};
use std::fmt;

pub(super) fn object<'a>(
    v: &'a Value,
    keys: &[&str],
    issue: PolicyIssue,
) -> Result<&'a Map<String, Value>, PolicyIssue> {
    let map = v.as_object().ok_or(issue)?;
    if map.keys().any(|key| !keys.contains(&key.as_str())) {
        return Err(issue);
    }
    Ok(map)
}
pub(super) fn text<'a>(
    map: &'a Map<String, Value>,
    key: &str,
    issue: PolicyIssue,
) -> Result<&'a str, PolicyIssue> {
    map.get(key).and_then(Value::as_str).ok_or(issue)
}
pub(super) fn optional_text<'a>(
    map: &'a Map<String, Value>,
    key: &str,
    issue: PolicyIssue,
) -> Result<&'a str, PolicyIssue> {
    map.get(key).map_or(Ok(""), |v| v.as_str().ok_or(issue))
}
pub(super) fn flag(
    map: &Map<String, Value>,
    key: &str,
    default: bool,
    issue: PolicyIssue,
) -> Result<bool, PolicyIssue> {
    map.get(key)
        .map_or(Ok(default), |v| v.as_bool().ok_or(issue))
}
pub(super) fn strings(v: &Value, issue: PolicyIssue) -> Result<Vec<String>, PolicyIssue> {
    if let Some(text) = v.as_str() {
        return Ok(vec![text.into()]);
    }
    v.as_array()
        .ok_or(issue)?
        .iter()
        .map(|v| v.as_str().map(str::to_owned).ok_or(issue))
        .collect()
}
pub(super) fn label(s: &str) -> bool {
    !s.is_empty() && s.len() <= 128 && !s.chars().any(char::is_control)
}

pub(super) struct Unique(pub Value);
impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Value;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("JSON without duplicate keys")
            }
            fn visit_bool<E: Error>(self, v: bool) -> Result<Value, E> {
                Ok(Value::Bool(v))
            }
            fn visit_i64<E: Error>(self, v: i64) -> Result<Value, E> {
                Ok(v.into())
            }
            fn visit_u64<E: Error>(self, v: u64) -> Result<Value, E> {
                Ok(v.into())
            }
            fn visit_f64<E: Error>(self, v: f64) -> Result<Value, E> {
                serde_json::Number::from_f64(v)
                    .map(Value::Number)
                    .ok_or_else(|| E::custom("Invalid number"))
            }
            fn visit_str<E: Error>(self, v: &str) -> Result<Value, E> {
                Ok(Value::String(v.into()))
            }
            fn visit_string<E: Error>(self, v: String) -> Result<Value, E> {
                Ok(Value::String(v))
            }
            fn visit_unit<E: Error>(self) -> Result<Value, E> {
                Ok(Value::Null)
            }
            fn visit_none<E: Error>(self) -> Result<Value, E> {
                Ok(Value::Null)
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
                let mut values = Vec::new();
                while let Some(v) = seq.next_element::<Unique>()? {
                    values.push(v.0);
                }
                Ok(Value::Array(values))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
                let mut values = Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(A::Error::custom("Duplicate JSON key"));
                    }
                    values.insert(key, map.next_value::<Unique>()?.0);
                }
                Ok(Value::Object(values))
            }
        }
        d.deserialize_any(V).map(Self)
    }
}
