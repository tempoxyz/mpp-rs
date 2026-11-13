//! The `Identity-Required` header: the identities a route's payment check
//! requires, as an RFC 9651 structured-field list.

use sfv::{BareItem, InnerList, Item, KeyRef, ListEntry, ListSerializer, StringRef, TokenRef};

use super::Requirement;

/// The response header in which a 402 lists the identities its payment check requires.
pub const HEADER: &str = "Identity-Required";

/// A requirement that cannot be sent in a structured-field list.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("identity requirement cannot be serialized: {0}")]
pub struct InvalidRequirement(String);

/// Serializes requirements as a structured-field list: each type token with
/// an `issuer` string parameter when set. Returns an empty string for none.
///
/// Fails for a type that is not a token or an issuer that is not a
/// structured-field string.
pub fn serialize(requirements: &[Requirement]) -> Result<String, InvalidRequirement> {
    let mut serializer = ListSerializer::new();
    for requirement in requirements {
        let kind = TokenRef::from_str(&requirement.kind)
            .map_err(|_| InvalidRequirement(format!("type {:?}", requirement.kind)))?;
        let item = serializer.bare_item(kind);
        if let Some(issuer) = &requirement.issuer {
            let value = StringRef::from_str(issuer)
                .map_err(|_| InvalidRequirement(format!("issuer {issuer:?}")))?;
            let key = KeyRef::constant("issuer");
            item.parameter(key, value);
        }
    }
    Ok(serializer.finish().unwrap_or_default())
}

/// Parses an `Identity-Required` value, skipping members that are not
/// requirements. A malformed value has none.
pub fn parse(value: Option<&str>) -> Vec<Requirement> {
    let Some(value) = value.filter(|value| !value.is_empty()) else {
        return Vec::new();
    };
    let Ok(list) = sfv::Parser::new(value).parse::<sfv::List>() else {
        return Vec::new();
    };
    list.iter()
        .filter_map(|member| {
            let ListEntry::Item(item) = member else {
                return None;
            };
            let BareItem::Token(kind) = &item.bare_item else {
                return None;
            };
            let issuer = item.params.iter().find_map(|(key, value)| match value {
                BareItem::String(issuer) if key.as_str() == "issuer" => {
                    Some(issuer.as_str().to_owned())
                }
                _ => None,
            });
            Some(Requirement {
                kind: kind.as_str().to_owned(),
                issuer,
            })
        })
        .collect()
}

/// Returns the distinct requirements of several lists, in first-seen order.
pub fn merge<'a>(lists: impl IntoIterator<Item = &'a [Requirement]>) -> Vec<Requirement> {
    let mut merged: Vec<Requirement> = Vec::new();
    for requirement in lists.into_iter().flatten() {
        if !merged.contains(requirement) {
            merged.push(requirement.clone());
        }
    }
    merged
}

/// Headers that list requirements as a structured-field list, whose values
/// [`any_of`](super::any_of) groups into one inner list of alternatives.
pub(crate) const ALTERNATIVE_HEADERS: &[&str] = &["identity-attestation-required"];

/// Combines the values the rejected members of an `any_of` sent in one
/// requirements header, as mppx's `Requirements.alternatives`:
///
/// - Each value is one item or one inner list: their items, deduplicated,
///   become one inner list of alternatives, any one of which meets it (a
///   single item stays bare).
/// - Otherwise (a member lists several requirements, or a value is
///   malformed): the values are kept as they are, comma-separated, so a client
///   asks for more than the route needs, never less.
pub(crate) fn alternatives(values: &[String]) -> String {
    let joined = || values.join(", ");
    let mut items: Vec<Item> = Vec::new();
    for value in values {
        let Ok(list) = sfv::Parser::new(value.as_str()).parse::<sfv::List>() else {
            return joined();
        };
        let [member] = list.as_slice() else {
            return joined();
        };
        match member {
            ListEntry::Item(item) => items.push(item.clone()),
            ListEntry::InnerList(inner) => items.extend(inner.items.iter().cloned()),
        }
    }
    let mut unique: Vec<(String, Item)> = Vec::new();
    for item in items {
        let key = serialize_entries(&[ListEntry::Item(item.clone())]);
        if !unique.iter().any(|(seen, _)| *seen == key) {
            unique.push((key, item));
        }
    }
    let entries = if unique.len() == 1 {
        vec![ListEntry::Item(unique.remove(0).1)]
    } else {
        vec![ListEntry::InnerList(InnerList::new(
            unique.into_iter().map(|(_, item)| item).collect(),
        ))]
    };
    serialize_entries(&entries)
}

fn serialize_entries(entries: &[ListEntry]) -> String {
    let mut serializer = ListSerializer::new();
    serializer.members(entries);
    serializer.finish().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_types_with_issuers() {
        let value = serialize(&[
            Requirement::new("tempo-id").with_issuer("https://id.tempo.xyz"),
            Requirement::new("kyc"),
        ])
        .unwrap();
        assert_eq!(value, r#"tempo-id;issuer="https://id.tempo.xyz", kyc"#);
    }

    #[test]
    fn serializes_none_as_empty() {
        assert_eq!(serialize(&[]).unwrap(), "");
    }

    #[test]
    fn rejects_non_token_types() {
        assert!(serialize(&[Requirement::new("not a token")]).is_err());
        assert!(serialize(&[Requirement::new("kyc").with_issuer("caf\u{e9}")]).is_err());
    }

    #[test]
    fn parses_round_trip_and_skips_non_requirements() {
        let parsed = parse(Some(
            r#"tempo-id;issuer="https://id.tempo.xyz", "string", (a b), kyc;issuer=tok, email"#,
        ));
        assert_eq!(
            parsed,
            vec![
                Requirement::new("tempo-id").with_issuer("https://id.tempo.xyz"),
                Requirement::new("kyc"),
                Requirement::new("email"),
            ]
        );
        assert!(parse(Some("(((")).is_empty());
        assert!(parse(None).is_empty());
    }

    #[test]
    fn merges_distinct_requirements_in_order() {
        let a = [Requirement::new("kyc"), Requirement::new("email")];
        let b = [Requirement::new("email"), Requirement::new("phone")];
        assert_eq!(
            merge([&a[..], &b[..]]),
            vec![
                Requirement::new("kyc"),
                Requirement::new("email"),
                Requirement::new("phone")
            ]
        );
    }

    #[test]
    fn groups_alternatives_into_one_inner_list() {
        let value = alternatives(&[
            r#"email;issuer="https://a.example""#.to_owned(),
            r#"email;issuer="https://b.example""#.to_owned(),
            r#"email;issuer="https://a.example""#.to_owned(),
        ]);
        assert_eq!(
            value,
            r#"(email;issuer="https://a.example" email;issuer="https://b.example")"#
        );
        assert_eq!(
            alternatives(&[r#"email;issuer="https://a.example""#.to_owned()]),
            r#"email;issuer="https://a.example""#
        );
        assert_eq!(
            alternatives(&["a, b".to_owned(), "c".to_owned()]),
            "a, b, c"
        );
    }
}
