//! Token-kind checks for the credentials this CLI stores and prints.
//!
//! fleet's tokens are forgs opaque tokens under the brand `prf`, plus fleet's
//! one app kind, the node token (`prfn1_…`). The format is built here from
//! forgs directly rather than borrowed from the coordinator, so the client
//! paths do not need the server crate to tell a session token from a node
//! token. `fleet_coordinator::identity::token_format` builds the same format;
//! a unit test pins the two together.

use std::sync::OnceLock;

use forgs::{OpaqueToken, TokenFormat, TokenKind, TokenUse};

/// Label of fleet's node app kind.
pub const NODE_KIND: &str = "node";

/// fleet's token format: brand `prf`, plus the `node` app kind (tag `n`).
///
/// # Panics
///
/// Never: the format is a constant and a unit test builds it.
#[must_use]
pub fn format() -> &'static TokenFormat {
    static FORMAT: OnceLock<TokenFormat> = OnceLock::new();
    FORMAT.get_or_init(|| {
        let mut b = TokenFormat::builder("prf");
        b.app_kind(NODE_KIND, "n", TokenUse::Connection);
        b.build().expect("fleet's token format is valid")
    })
}

/// The node token kind.
///
/// # Panics
///
/// Never: [`format`] registers it.
#[must_use]
pub fn node_kind() -> TokenKind {
    TokenKind::App(format().app_kind(NODE_KIND).expect("node kind registered"))
}

/// Whether `s` parses as a token of `kind`.
#[must_use]
pub fn is_kind(s: &str, kind: TokenKind) -> bool {
    format().parse(s).is_ok_and(|t| t.kind() == kind)
}

/// Whether `s` is a user session token (`prfs1_…`).
#[must_use]
pub fn is_session(s: &str) -> bool {
    is_kind(s, TokenKind::Session)
}

/// Whether `s` is a refresh token (`prfr1_…`).
#[must_use]
pub fn is_refresh(s: &str) -> bool {
    is_kind(s, TokenKind::Refresh)
}

/// Whether `s` is an API key (`prfk1_…`).
#[must_use]
pub fn is_api_key(s: &str) -> bool {
    is_kind(s, TokenKind::ApiKey)
}

/// Whether `s` is a workload token (`prfw1_…`).
#[must_use]
pub fn is_workload(s: &str) -> bool {
    is_kind(s, TokenKind::Workload)
}

/// Whether `s` is a node token (`prfn1_…`).
#[must_use]
pub fn is_node(s: &str) -> bool {
    is_kind(s, node_kind())
}

/// Mint a random token of `kind` (tests and fixtures).
#[must_use]
pub fn mint(kind: TokenKind) -> OpaqueToken {
    format().mint(kind)
}

/// Mint a random token of `kind`, rendered.
#[must_use]
pub fn mint_string(kind: TokenKind) -> String {
    mint(kind).to_secret_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefixes_match_the_coordinators_format() {
        let theirs = fleet_coordinator::identity::token_format();
        for kind in [
            TokenKind::Session,
            TokenKind::Refresh,
            TokenKind::ApiKey,
            TokenKind::Workload,
            TokenKind::DeviceSecret,
        ] {
            assert_eq!(format().prefix(kind), theirs.prefix(kind));
        }
        assert_eq!(
            format().prefix(node_kind()),
            theirs.prefix(fleet_coordinator::identity::node_token_kind(&theirs))
        );
        assert!(mint_string(node_kind()).starts_with("prfn1_"));
    }

    #[test]
    fn kinds_are_told_apart() {
        let s = mint_string(TokenKind::Session);
        assert!(is_session(&s) && !is_refresh(&s) && !is_node(&s));
        assert!(is_node(&mint_string(node_kind())));
        assert!(!is_session("garbage"));
    }
}
