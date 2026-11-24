//! The reserved `opaque` key that marks a challenge whose method accepts some
//! of its credentials for a while after it expires, as mppx's
//! `_mppx_expiry_grace`.
//!
//! The challenge HMAC covers `opaque`, so a challenge issued without the
//! marker (by an earlier release, or with no grace configured) never gets that
//! grace.

// Only the Tempo server and client use every helper.
#![cfg_attr(not(all(feature = "server", feature = "tempo")), allow(dead_code))]

use super::types::Base64UrlJson;

/// Reserved metadata key of the expiry grace marker.
pub(crate) const EXPIRY_GRACE_KEY: &str = "_mppx_expiry_grace";

/// Whether `opaque` carries the expiry grace marker.
pub(crate) fn has_expiry_grace(opaque: Option<&Base64UrlJson>) -> bool {
    opaque
        .and_then(|opaque| opaque.decode_value().ok())
        .is_some_and(|meta| meta.get(EXPIRY_GRACE_KEY).and_then(|v| v.as_str()) == Some("1"))
}

/// `opaque` with the expiry grace marker when `grace` is true, and without
/// any copy of it otherwise. `opaque` that is not a JSON object is returned
/// unchanged.
pub(crate) fn with_expiry_grace(
    opaque: Option<&Base64UrlJson>,
    grace: bool,
) -> Option<Base64UrlJson> {
    let mut meta = match opaque.map(Base64UrlJson::decode_value) {
        None => serde_json::Map::new(),
        Some(Ok(serde_json::Value::Object(meta))) => meta,
        Some(_) => return opaque.cloned(),
    };
    if !grace && !meta.contains_key(EXPIRY_GRACE_KEY) {
        return opaque.cloned();
    }
    meta.remove(EXPIRY_GRACE_KEY);
    if grace {
        meta.insert(EXPIRY_GRACE_KEY.into(), "1".into());
    }
    if meta.is_empty() && opaque.is_none() {
        return None;
    }
    Base64UrlJson::from_value(&serde_json::Value::Object(meta))
        .ok()
        .or_else(|| opaque.cloned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opaque(value: serde_json::Value) -> Base64UrlJson {
        Base64UrlJson::from_value(&value).unwrap()
    }

    #[test]
    fn marks_and_unmarks_opaque() {
        let marked = with_expiry_grace(None, true).unwrap();
        assert!(has_expiry_grace(Some(&marked)));
        assert_eq!(
            with_expiry_grace(Some(&marked), false),
            Some(opaque(serde_json::json!({})))
        );
        assert_eq!(with_expiry_grace(None, false), None);

        let route = opaque(serde_json::json!({ "plan": "pro" }));
        let marked = with_expiry_grace(Some(&route), true).unwrap();
        assert!(has_expiry_grace(Some(&marked)));
        assert!(!has_expiry_grace(Some(&route)));
        assert_eq!(with_expiry_grace(Some(&marked), false), Some(route.clone()));
        assert_eq!(with_expiry_grace(Some(&route), false), Some(route.clone()));
    }

    #[test]
    fn only_the_exact_marker_counts() {
        assert!(!has_expiry_grace(None));
        assert!(!has_expiry_grace(Some(&opaque(
            serde_json::json!({ EXPIRY_GRACE_KEY: "0" })
        ))));
        assert!(!has_expiry_grace(Some(&opaque(
            serde_json::json!({ EXPIRY_GRACE_KEY: 1 })
        ))));
        assert!(!has_expiry_grace(Some(&Base64UrlJson::from_raw(
            "not base64!"
        ))));
    }
}
