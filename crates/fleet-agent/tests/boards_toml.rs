//! End-to-end parse of a realistic `boards.toml` fixture (architecture §8).

use fleet_agent::config::BoardsConfig;
use fleet_proto::{BoardName, PowerKind};

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
