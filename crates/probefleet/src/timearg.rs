//! Duration and deadline parsing for the CLI's time flags.
//!
//! Two shapes, both used by `grant` and `ctl delegate`:
//!
//! * `--ttl 2h` — a *relative* duration (`90s`, `30m`, `2h`, `7d`, or bare
//!   seconds), and
//! * `--until 2026-12-31` — an *absolute* deadline, as a civil date or an
//!   epoch-seconds integer.
//!
//! Deliberately dependency-free. Pulling `chrono`/`time` into `probefleet` to
//! parse `YYYY-MM-DD` would be a poor trade: the days-from-civil algorithm
//! below is fifteen lines and exact, and a date flag is the only calendar
//! arithmetic in the tree.
//!
//! Dates are interpreted as **UTC midnight**. Stated rather than assumed: a
//! grant that expires "on the 31st" in one timezone and not another is a
//! support ticket, and every other timestamp the fleet stores is epoch seconds.

/// Parse a duration: bare seconds, or a `s`/`m`/`h`/`d` suffix.
///
/// # Errors
///
/// Returns a human-readable message for an empty, malformed or zero duration.
pub fn parse_duration(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty duration".to_owned());
    }
    let (digits, mult) = match s.chars().last() {
        Some('s') => (&s[..s.len() - 1], 1u64),
        Some('m') => (&s[..s.len() - 1], 60),
        Some('h') => (&s[..s.len() - 1], 3_600),
        Some('d') => (&s[..s.len() - 1], 86_400),
        _ => (s, 1),
    };
    // Note the digits are *not* trimmed: leading/trailing space around the
    // whole value is fine, but `2 h` is a typo, not a duration.
    let n: u64 = digits
        .parse()
        .map_err(|_| format!("invalid duration `{s}`: expected e.g. 90s, 30m, 2h, 7d"))?;
    if n == 0 {
        return Err("duration must be greater than zero".to_owned());
    }
    n.checked_mul(mult)
        .ok_or_else(|| format!("duration `{s}` overflows"))
}

/// Parse an absolute deadline: `YYYY-MM-DD` (UTC midnight) or epoch seconds.
///
/// `now` is passed in rather than read from the clock so the "in the past"
/// check is testable, and so a caller that has already sampled the time uses
/// one consistent value.
///
/// # Errors
///
/// Returns a human-readable message for a malformed date, an impossible one
/// (`2026-02-30`), or a deadline that has already passed.
pub fn parse_until(s: &str, now: u64) -> Result<u64, String> {
    let s = s.trim();
    let epoch = if let Some(rest) = s.strip_prefix('@') {
        rest.parse::<u64>()
            .map_err(|_| format!("invalid epoch `{s}`"))?
    } else if s.len() == 10 && s.as_bytes()[4] == b'-' && s.as_bytes()[7] == b'-' {
        parse_civil_date(s)?
    } else {
        s.parse::<u64>()
            .map_err(|_| format!("invalid deadline `{s}`: expected YYYY-MM-DD or epoch seconds"))?
    };
    if epoch <= now {
        return Err(format!("deadline `{s}` is in the past"));
    }
    Ok(epoch)
}

/// `YYYY-MM-DD` → epoch seconds at UTC midnight.
fn parse_civil_date(s: &str) -> Result<u64, String> {
    let bad = || format!("invalid date `{s}`: expected YYYY-MM-DD");
    let y: i64 = s[0..4].parse().map_err(|_| bad())?;
    let m: u32 = s[5..7].parse().map_err(|_| bad())?;
    let d: u32 = s[8..10].parse().map_err(|_| bad())?;
    if !(1..=12).contains(&m) || d < 1 || d > days_in_month(y, m) {
        return Err(bad());
    }
    let days = days_from_civil(y, m, d);
    if days < 0 {
        return Err(format!("date `{s}` predates the epoch"));
    }
    u64::try_from(days * 86_400).map_err(|_| bad())
}

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

fn days_in_month(y: i64, m: u32) -> u32 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap(y) => 29,
        2 => 28,
        _ => 0,
    }
}

/// Howard Hinnant's `days_from_civil`: days since 1970-01-01 for a proleptic
/// Gregorian date. Exact for every year in range, and the reason this module
/// needs no calendar crate.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let m = i64::from(m);
    let d = i64::from(d);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_with_and_without_suffixes() {
        assert_eq!(parse_duration("90s").unwrap(), 90);
        assert_eq!(parse_duration("30m").unwrap(), 1_800);
        assert_eq!(parse_duration("2h").unwrap(), 7_200);
        assert_eq!(parse_duration("7d").unwrap(), 604_800);
        assert_eq!(parse_duration("7200").unwrap(), 7_200);
        assert_eq!(parse_duration(" 2h ").unwrap(), 7_200);
    }

    #[test]
    fn malformed_and_zero_durations_are_refused() {
        for bad in ["", "  ", "2y", "abc", "0", "0h", "-5", "2 h"] {
            assert!(parse_duration(bad).is_err(), "{bad} should not parse");
        }
    }

    /// Checked against known epoch values, so a bug in `days_from_civil` cannot
    /// hide behind a self-consistent implementation.
    #[test]
    fn civil_dates_map_to_known_epochs() {
        assert_eq!(parse_until("1970-01-02", 0).unwrap(), 86_400);
        assert_eq!(parse_until("2000-01-01", 0).unwrap(), 946_684_800);
        assert_eq!(parse_until("2024-02-29", 0).unwrap(), 1_709_164_800);
        assert_eq!(parse_until("2026-12-31", 0).unwrap(), 1_798_675_200);
    }

    #[test]
    fn epoch_seconds_are_accepted_verbatim() {
        assert_eq!(parse_until("2000000000", 0).unwrap(), 2_000_000_000);
        assert_eq!(parse_until("@2000000000", 0).unwrap(), 2_000_000_000);
    }

    /// A grant that expired before it was created is always a mistake, and a
    /// silent one if we merely stored it.
    #[test]
    fn a_deadline_in_the_past_is_refused() {
        let now = 1_798_675_200; // 2026-12-31
        assert!(parse_until("2020-01-01", now).is_err());
        assert!(
            parse_until("2026-12-31", now).is_err(),
            "exactly now is past"
        );
        assert!(parse_until("2027-01-01", now).is_ok());
    }

    #[test]
    fn impossible_dates_are_refused() {
        for bad in [
            "2026-02-30",
            "2025-02-29", // not a leap year
            "2026-13-01",
            "2026-00-10",
            "2026-01-00",
            "2026-1-1",
            "not-a-date",
        ] {
            assert!(parse_until(bad, 0).is_err(), "{bad} should not parse");
        }
        // ...but a real leap day is fine.
        assert!(parse_until("2028-02-29", 0).is_ok());
    }
}
