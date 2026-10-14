//! End-to-end parse of a realistic `boards.toml` fixture (architecture §8).

use probefleet_agent::config::BoardsConfig;
use probefleet_proto::{BoardName, PowerKind};

#[test]
fn parses_realistic_boards_fixture() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/boards.toml");
    let cfg = BoardsConfig::from_path(path).expect("fixture should parse");

    assert_eq!(cfg.boards.len(), 3);

    let nrf = cfg
        .board(&BoardName("nrf52840-dk-3".into()))
        .expect("nrf board present");
    assert_eq!(nrf.serial, "001050257890");
    assert_eq!(nrf.chip, "nRF52840_xxAA");
    // The board MODEL: what `board=<model>` matches, distinct from the chip.
    assert_eq!(nrf.model.as_deref(), Some("nrf52840dk"));
    assert_eq!(nrf.tags, vec!["nrf52", "bluetooth"]);
    assert!(nrf.exclusive);
    assert_eq!(
        nrf.power.to_power_kind(),
        PowerKind::Uhubctl {
            hub: "1-1".into(),
            port: 2
        }
    );

    let rp = cfg
        .board(&BoardName("rp2040-pico-1".into()))
        .expect("rp2040 board present");
    // exclusive defaults to true when omitted.
    assert!(rp.exclusive);
    // `model` is optional: a board that declares none simply cannot be reached
    // by a `board=` selector.
    assert!(rp.model.is_none());
    assert_eq!(
        rp.power.to_power_kind(),
        PowerKind::Gpio {
            chip: "gpiochip0".into(),
            line: 17
        }
    );

    let stm = cfg
        .board(&BoardName("stm32f4-disco-2".into()))
        .expect("stm32 board present");
    assert!(!stm.exclusive);
    assert_eq!(stm.power.to_power_kind(), PowerKind::None);
}

#[test]
fn fixture_passes_validation() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/boards.toml");
    let cfg = BoardsConfig::from_path(path).unwrap();
    cfg.validate().unwrap();
}

/// An empty `model` is rejected rather than silently meaning "none": a board
/// whose model is the empty string could never be selected (`board=` with an
/// empty value is a parse error) but would look declared.
#[test]
fn an_empty_model_is_refused() {
    let text = r#"
[[board]]
id     = "b1"
serial = "s1"
chip   = "c1"
model  = ""
"#;
    let err = BoardsConfig::from_str(text).unwrap_err();
    assert!(
        err.to_string().contains("empty model"),
        "unexpected error: {err}"
    );
}
