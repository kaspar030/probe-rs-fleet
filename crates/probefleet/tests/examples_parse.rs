//! The shipped `examples/*.toml` must parse through the real loaders.
//!
//! An example that has drifted from the code is worse than no example: it is
//! read as documentation and copied verbatim, so the first person to use it
//! discovers a bug that looks like theirs. These are cheap and they fail the
//! moment a field is renamed.

use std::path::PathBuf;

fn examples_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("examples")
}

/// `examples/fleet.toml` is the reference for the per-fleet layout, and it
/// deliberately shows every table populated at once: a laptop (`[user]` +
/// `[node]`) that also hosts a persistent sandbox (`[agent]`).
///
/// One file carrying all three is the case the read-modify-write rule exists
/// for, so the shipped reference must show that it is legal.
#[test]
fn fleet_example_parses_with_all_three_tables() {
    let path = examples_dir().join("fleet.toml");
    let text = std::fs::read_to_string(&path).unwrap();
    let file: probefleet::fleet_config::FleetFile = toml::from_str(&text).unwrap();

    assert_eq!(file.url, "https://fleet.example.com");
    let user = file.user.expect("[user] table");
    // The username is the fleet's own name; no provider id appears anywhere.
    assert_eq!(user.username.as_deref(), Some("kaspar"));
    // Acting in the personal org is the default, so `org` is shown commented.
    assert!(user.org.is_none());
    assert!(
        !text.contains("gh-"),
        "no GitHub-derived ids in the reference"
    );
    // The durable half of `[user]`. Shown populated because the example is
    // where a reader learns the field exists at all — and because it must be
    // parseable, not merely described in prose.
    let refresh = user
        .refresh_token
        .as_deref()
        .expect("[user].refresh_token in the reference file");
    assert!(refresh.starts_with("prfr1_"), "{refresh}");
    assert_ne!(refresh, user.session_token);

    let node = file.node.expect("[node] table");
    assert!(node.node_id.ends_with("/rpi-lab-1"), "{}", node.node_id);
    assert_eq!(node.coordinator_token_pubkey.len(), 64);
    // The two credentials are distinct values, which is the property the
    // example's prose is about.
    assert_ne!(user.session_token, node.node_token);

    let agent = file.agent.expect("[agent] table");
    assert_eq!(agent.name.as_deref(), Some("desk-bot"));
    // `expires` is a required field here, unlike `[user].expires`: a live
    // example that omitted it would not deserialise at all, which is exactly
    // what this assertion is for.
    assert!(agent.expires > 0);
    assert_ne!(agent.auth_key, agent.workload_token);
    assert!(agent.auth_key.starts_with("prfk1_"), "{}", agent.auth_key);
}

/// The `[agent]` block must teach the two rules a reader cannot infer from the
/// field names: the key has to be `--multi-use`, and storing it is a trust
/// decision about *this machine*.
#[test]
fn the_fleet_example_states_the_agent_tables_two_preconditions() {
    let path = examples_dir().join("fleet.toml");
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.contains("agent login"), "the writing verb is named");
    assert!(
        text.contains("--multi-use"),
        "the key requirement is stated"
    );
    // The CI rule must still be there, and must now name its exception rather
    // than contradicting the code. Asserted on the substantive sentence: a
    // laxer fallback would make this check pass on prose that had lost the
    // rule entirely.
    assert!(
        text.contains("`probe-rs-fleet ci login` writes\n# NOTHING here"),
        "the shipped example must keep stating that `ci login` persists nothing"
    );
    assert!(
        text.contains("deliberate, opt-in exception"),
        "...and must name `agent login` as its exception rather than contradicting it"
    );
}

/// The example must state what the refresh token can and cannot do, and what
/// revokes it.
///
/// Prose as a control, the same way the `audience` test below is: a reader who
/// takes `refresh_token` for "a second session token" will not understand why
/// it survives a `logout` on one machine, or why it is worth more to an
/// attacker than the line above it.
#[test]
fn the_fleet_example_states_what_the_refresh_token_can_and_cannot_do() {
    let text = std::fs::read_to_string(examples_dir().join("fleet.toml")).unwrap();
    assert!(
        text.contains("logout --all"),
        "the example must name what revokes the refresh token"
    );
    assert!(
        text.contains("opens no connection"),
        "...and what it cannot do"
    );
    assert!(
        text.contains("does NOT consume it"),
        "...and that redemption is non-rotating, which is why concurrent \
         invocations do not race"
    );
    assert!(
        text.contains("OPTIONAL"),
        "a file without the field must be documented as valid"
    );
}

/// `examples/node.toml` is entirely commented out, so it must parse as the
/// all-defaults case the agent treats an absent file as.
///
/// `adopt` in particular must stay commented: an example that switched a
/// reader's node to `auto` merely by being copied would share probes nobody
/// asked to share.
#[test]
fn node_example_parses_as_all_defaults() {
    let path = examples_dir().join("node.toml");
    let text = std::fs::read_to_string(&path).unwrap();
    let settings: probefleet::roles::node_run::NodeSettings = toml::from_str(&text).unwrap();
    assert!(settings.boards_path.is_none());
    assert!(settings.heartbeat_secs.is_none());
    assert!(settings.discovery_secs.is_none());
    assert!(settings.adopt.is_none());
    assert!(!settings.erase_on_release);
}

/// The `adopt` key must be *documented* in the example even though it is
/// commented out, and both of its values must be ones the code accepts — a
/// reader uncommenting the line has to get a file that loads.
#[test]
fn the_node_example_documents_both_adopt_policies_and_they_parse() {
    let path = examples_dir().join("node.toml");
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.contains("adopt"), "the example must document `adopt`");
    assert!(text.contains("discovery_secs"));

    for policy in ["auto", "declared"] {
        assert!(
            text.contains(&format!("\"{policy}\"")),
            "the example must name the `{policy}` policy"
        );
        let uncommented = text
            .replace("# adopt = ", "adopt = ")
            .replace("adopt = \"declared\"", &format!("adopt = \"{policy}\""));
        let settings: probefleet::roles::node_run::NodeSettings =
            toml::from_str(&uncommented).unwrap();
        assert_eq!(
            settings.adopt.map(probefleet_proto::AdoptPolicy::as_str),
            Some(policy),
            "uncommenting `adopt` must yield a file that loads"
        );
    }
}

/// `examples/coordinator.toml` must load through the real loader, including the
/// `[[auth.providers]]` block once uncommented — the block is the one part of
/// it a reader has to edit, so a typo there costs the most.
#[test]
fn coordinator_example_loads_and_its_providers_block_works_uncommented() {
    let path = examples_dir().join("coordinator.toml");
    let dir = tempfile::tempdir().unwrap();
    let secret = dir.path().join("github.secret");
    std::fs::write(&secret, "s3cret\n").unwrap();
    let csrf = dir.path().join("csrf.secret");
    std::fs::write(&csrf, "cd".repeat(32)).unwrap();
    // The example points `signing_key_path` at a deployment path that does not
    // exist in a checkout, so swap in an inline seed. Everything else — every
    // key a reader might typo — is loaded verbatim.
    let text = std::fs::read_to_string(&path)
        .unwrap()
        .lines()
        .map(|line| {
            if line.starts_with("signing_key_path") {
                format!("signing_key_hex = \"{}\"", "ab".repeat(32))
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");

    let cfg = probefleet::config::load_coordinator_config_from_str(&text).unwrap();
    cfg.validate().unwrap();
    // Commented out, so login is unconfigured — which the example says is a
    // supported deployment.
    assert!(cfg.auth.providers.is_empty());
    assert!(cfg.csrf_secret.is_none());

    // Uncomment the provider block (and the csrf secret) the way a reader
    // would: strip one `# ` from the header and from every *key* line, leaving
    // prose comments (which start `# #`) as comments. The deployment paths are
    // swapped for files that exist.
    let uncommented: String = text
        .lines()
        .map(|line| {
            let t = line.trim_start();
            if t.starts_with("# client_secret_path") {
                format!("client_secret_path = \"{}\"", secret.display())
            } else if t.starts_with("# csrf_secret_path") {
                format!("csrf_secret_path = \"{}\"", csrf.display())
            } else if t.starts_with("# [[auth.providers]]")
                || t.starts_with("# kind")
                || t.starts_with("# client_id")
            {
                t.trim_start_matches("# ").to_owned()
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");

    let cfg = probefleet::config::load_coordinator_config_from_str(&uncommented).unwrap();
    cfg.validate().unwrap();
    assert_eq!(cfg.auth.providers.len(), 1);
    let p = &cfg.auth.providers[0];
    assert_eq!(p.name, "github");
    assert_eq!(p.client_id, "Iv1.0123456789abcdef");
    assert_eq!(p.client_secret, "s3cret");
    assert_eq!(cfg.csrf_secret.as_deref().map(<[u8]>::len), Some(32));
}

/// The commented `refresh_token_ttl_secs` line must uncomment into a value the
/// loader accepts, and must match the code's default — an example that showed
/// a different figure would be read as the default and quietly disagree.
#[test]
fn the_coordinator_example_documents_the_refresh_token_ttl() {
    let path = examples_dir().join("coordinator.toml");
    let text = std::fs::read_to_string(&path)
        .unwrap()
        .lines()
        .map(|line| {
            if line.starts_with("signing_key_path") {
                format!("signing_key_hex = \"{}\"", "ab".repeat(32))
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");

    assert!(
        text.contains("# refresh_token_ttl_secs = 2592000"),
        "the knob must be documented with its default"
    );
    assert!(
        text.contains("logout --all"),
        "...and the example must name what revokes a refresh token, since the \
         TTL is only half the bound"
    );

    // Commented out, so the code's default applies — and the two must agree.
    let cfg = probefleet::config::load_coordinator_config_from_str(&text).unwrap();
    assert_eq!(cfg.refresh_token_ttl_secs, 30 * 24 * 3600);

    // Uncommenting it yields a file that loads and validates.
    let uncommented = text.replace(
        "# refresh_token_ttl_secs = 2592000",
        "refresh_token_ttl_secs = 604800",
    );
    let cfg = probefleet::config::load_coordinator_config_from_str(&uncommented).unwrap();
    cfg.validate().unwrap();
    assert_eq!(cfg.refresh_token_ttl_secs, 604_800);
}

/// The `[github_actions]` block must uncomment into TOML the **real** loader
/// accepts, exactly as the `[[auth.providers]]` block above must.
///
/// The two blocks earn this treatment for the same reason: they are the parts
/// of the file a reader has to edit, so a typo in one costs the most. This one
/// has a sharper edge — `audience` is *required* and has no default, for the
/// replay reason the block itself explains, so a reader who uncomments the
/// block but not that key must get a clear config error rather than a fleet
/// that accepts GitHub's fleet-unspecific default.
#[test]
fn coordinator_example_github_actions_block_works_uncommented() {
    let path = examples_dir().join("coordinator.toml");
    let text = std::fs::read_to_string(&path)
        .unwrap()
        .lines()
        .map(|line| {
            if line.starts_with("signing_key_path") {
                format!("signing_key_hex = \"{}\"", "ab".repeat(32))
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");

    // Commented out by default: a fleet with no CI is supported, and the
    // exchange then answers a named 503.
    let cfg = probefleet::config::load_coordinator_config_from_str(&text).unwrap();
    assert!(cfg.github_actions.is_none());

    // Uncomment the block the way a reader would: strip one `# ` from the
    // table header and from every *key* line, leaving the prose comments
    // (which start `# #`) as comments. That is the same mechanical rule the
    // providers test above uses, which is why the two blocks' comment style
    // must stay identical.
    let uncommented: String = text
        .lines()
        .map(|line| {
            let t = line.trim_start();
            if t.starts_with("# [github_actions]")
                || t.starts_with("# audience")
                || t.starts_with("# issuer")
                || t.starts_with("# jwks_url")
                || t.starts_with("# jwks_refresh_secs")
                || t.starts_with("# jwks_min_refetch_secs")
                || t.starts_with("# workload_token_ttl_secs")
            {
                t.trim_start_matches("# ").to_owned()
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");

    let cfg = probefleet::config::load_coordinator_config_from_str(&uncommented).unwrap();
    cfg.validate().unwrap();
    let gha = cfg
        .github_actions
        .expect("[github_actions] parsed once uncommented");
    assert_eq!(gha.audience, "https://fleet.example");
    // Every optional key resolves to its documented default, whether the
    // reader left it commented or not.
    assert_eq!(gha.issuer, "https://token.actions.githubusercontent.com");
    assert_eq!(
        gha.jwks_url,
        "https://token.actions.githubusercontent.com/.well-known/jwks"
    );
    assert_eq!(gha.jwks_refresh_secs, 3600);
    assert_eq!(gha.jwks_min_refetch_secs, 60);
    assert_eq!(gha.workload_token_ttl_secs, 3600);

    // The block's own load-bearing claim: without `audience` it does not load.
    let without_audience: String = uncommented
        .lines()
        .filter(|l| !l.trim_start().starts_with("audience"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        probefleet::config::load_coordinator_config_from_str(&without_audience).is_err(),
        "`audience` is required, and the example must not parse without it"
    );
}

/// The example must say, in the file itself, why `audience` has no default.
///
/// The prose is the control here: a reader who sets it to something arbitrary
/// gets a fleet that accepts tokens minted for another service under the same
/// GitHub owner. That is not recoverable from the key name alone.
#[test]
fn the_coordinator_example_explains_why_the_audience_has_no_default() {
    let path = examples_dir().join("coordinator.toml");
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.contains("[github_actions]"));
    assert!(
        text.contains("https://github.com/<owner>"),
        "the example must name GitHub's fleet-unspecific default audience"
    );
    assert!(
        text.contains("replayable"),
        "…and say what accepting it would cost"
    );
    assert!(
        text.contains("grant --repo"),
        "the per-repo grant is the other half a reader needs"
    );
}

/// `examples/boards.toml` is a full worked inventory, not a stub, so it must
/// pass the agent's validation as well as its parser.
#[test]
fn boards_example_parses_and_validates() {
    let path = examples_dir().join("boards.toml");
    let text = std::fs::read_to_string(&path).unwrap();
    let boards = probefleet_agent::config::BoardsConfig::from_str(&text).unwrap();
    boards.validate().unwrap();
    assert!(!boards.boards.is_empty());
    // The worked board must declare a `model`: it is the field a reader is
    // most likely to omit, and without it `board=<model>` matches nothing.
    assert!(
        boards.boards.iter().any(|b| b.model.is_some()),
        "the boards example must show a declared board model"
    );
}

/// The `boards.toml` example's prose is load-bearing: revision 2 demoted the
/// file from admission control to annotation, and made board ids node-local
/// rather than fleet-global. A reader who copies the old wording gets a mental
/// model that breaks the moment two machines plug in the same dev kit.
#[test]
fn the_boards_example_does_not_still_claim_global_ids_or_admission_control() {
    let path = examples_dir().join("boards.toml");
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(
        !text.contains("unique across the whole fleet"),
        "board ids are unique within their node, not across the fleet (§6.1)"
    );
    assert!(text.contains("WITHIN THIS NODE"));
    assert!(
        text.contains("adopt"),
        "the file must explain the adoption policy that replaced it as a gate"
    );
}

/// The deleted files must stay deleted: leaving them would send a reader
/// straight back to the layout revision 2 replaced.
#[test]
fn the_superseded_examples_are_gone() {
    assert!(!examples_dir().join("client.toml").exists());
    assert!(!examples_dir().join("agent.toml").exists());
}

/// The example must name the helper that writes entries into it, and must say
/// what the helper will *not* do.
///
/// Under `adopt = "declared"` — the recommended lab/CI policy — hand-editing
/// this file was the only path, and this example is where a reader looks first.
/// The append-only caveat has to travel with the recommendation: someone who
/// learns `node board add` here and then goes looking for `node board remove`
/// should find the answer in the same paragraph.
#[test]
fn the_boards_example_names_the_helper_and_its_append_only_limit() {
    let text = std::fs::read_to_string(examples_dir().join("boards.toml")).unwrap();
    assert!(text.contains("node board add"), "{text}");
    assert!(text.contains("node board list"), "{text}");
    assert!(
        text.contains("appends") || text.contains("APPENDS"),
        "the example must say the helper only appends"
    );
    assert!(
        text.contains("restart"),
        "boards.toml is read once at agent startup; the example must say so"
    );
}
