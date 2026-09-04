//! Short human-typed approval codes (`ABCD-1234`) for interactive node
//! enrollment (architecture §4.2 rung 3, §6.4).
//!
//! A headless machine prints one of these; a human reads it off that terminal
//! and types it into `probe-rs-fleet node approve` on a machine where they are
//! logged in. So the alphabet is chosen for a human reading a small font over
//! a serial console, not for density: **Crockford base32**
//! (`0123456789ABCDEFGHJKMNPQRSTVWXYZ`), which omits `I`, `L`, `O` and `U`.
//!
//! Three properties, in the order they matter:
//!
//! * **Uniform.** [`generate`] takes five bits per symbol from the OS random
//!   source. 32 divides 256 exactly, so a mask is uniform here and no
//!   rejection is needed — but the assertion is load-bearing rather than
//!   incidental, because a shorter alphabet reduced with `%` would make its
//!   first symbols likelier and quietly cost part of the ~40 bits this design
//!   leans on. A debug assertion pins the property to the alphabet.
//! * **Forgiving on input.** [`normalise`] folds case, strips hyphens and
//!   whitespace, and maps the confusables Crockford defines (`I`/`L` → `1`,
//!   `O` → `0`), so `abcd-1234`, `ABCD1234` and `ABCD-l234` are one code.
//! * **Canonical in storage.** The database always holds the *normalised*
//!   form; [`display`] is a pure function of it. There is therefore exactly one
//!   string that can be looked up, and no path where two spellings of one code
//!   address two rows.

/// The Crockford base32 symbol alphabet: no `I`, `L`, `O` or `U`.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// How many symbols a user code has (~40 bits at 5 bits per symbol).
pub const CODE_LEN: usize = 8;

/// Mint a fresh user code in its normalised (hyphen-free) form.
///
/// # Panics
///
/// Panics if the OS random source fails, which is not a condition any caller
/// can meaningfully recover from — the same stance [`crate::OpaqueToken::mint`]
/// takes.
#[must_use]
pub fn generate() -> String {
    use rand_core::RngCore as _;

    // 256 % 32 == 0, so masking off five bits is a uniform draw. Asserted
    // rather than assumed: an alphabet whose length stops dividing 256 must
    // fail here loudly, not silently skew the distribution.
    debug_assert!(256 % ALPHABET.len() == 0, "alphabet length must divide 256");

    let mut buf = [0u8; CODE_LEN];
    rand_core::OsRng.fill_bytes(&mut buf);
    buf.iter()
        .map(|byte| char::from(ALPHABET[usize::from(byte & 0x1f)]))
        .collect()
}

/// Normalise a user-typed code to its canonical stored form.
///
/// Returns `None` for anything that is not exactly [`CODE_LEN`] symbols of the
/// alphabet once case, separators and Crockford confusables are folded. Both
/// the coordinator and the CLI run this **before** any lookup, so a lookup key
/// is always canonical.
#[must_use]
pub fn normalise(raw: &str) -> Option<String> {
    let mut out = String::with_capacity(CODE_LEN);
    for c in raw.chars() {
        if c == '-' || c == '_' || c.is_whitespace() {
            continue;
        }
        let c = c.to_ascii_uppercase();
        let folded = match c {
            // Crockford's decoding confusables. Folding them is what makes a
            // code read off a screen and typed by a tired human work.
            'I' | 'L' => '1',
            'O' => '0',
            other => other,
        };
        if !ALPHABET.contains(&u8::try_from(folded).ok()?) {
            return None;
        }
        out.push(folded);
        if out.len() > CODE_LEN {
            return None;
        }
    }
    (out.len() == CODE_LEN).then_some(out)
}

/// Render a normalised code for printing (`ABCD-1234`).
///
/// A pure function of the stored form: nothing is stored hyphenated, so the
/// display format can change without a migration.
#[must_use]
pub fn display(normalised: &str) -> String {
    if normalised.len() == CODE_LEN {
        format!("{}-{}", &normalised[..4], &normalised[4..])
    } else {
        normalised.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_codes_are_canonical_and_well_formed() {
        for _ in 0..256 {
            let code = generate();
            assert_eq!(code.len(), CODE_LEN);
            assert!(code.bytes().all(|b| ALPHABET.contains(&b)), "{code}");
            // The invariant every lookup depends on: what we mint is already
            // the form we store.
            assert_eq!(normalise(&code).as_deref(), Some(code.as_str()));
        }
    }

    #[test]
    fn distinct_codes_are_usually_distinct() {
        let a = generate();
        let b = generate();
        // 40 bits: a collision here means the RNG is broken, not unlucky.
        assert_ne!(a, b);
    }

    #[test]
    fn normalise_folds_case_separators_and_confusables() {
        let canonical = normalise("ABCD1234").unwrap();
        for spelling in [
            "ABCD-1234",
            "abcd1234",
            "abcd-1234",
            "  ABCD 1234 ",
            "ABCD-l234",
            "ABCD-I234",
            "abcd_1234",
        ] {
            assert_eq!(
                normalise(spelling).as_deref(),
                Some(canonical.as_str()),
                "{spelling}"
            );
        }
        // `O` folds to zero, so both spellings of a code containing one agree.
        assert_eq!(normalise("O1234567"), normalise("01234567"));
    }

    #[test]
    fn normalise_rejects_wrong_length_and_alphabet() {
        assert_eq!(normalise(""), None);
        assert_eq!(normalise("ABCD123"), None);
        assert_eq!(normalise("ABCD12345"), None);
        // `U` is deliberately not in Crockford's alphabet and is not folded.
        assert_eq!(normalise("ABCDU234"), None);
        assert_eq!(normalise("ABCD!234"), None);
        assert_eq!(normalise("ABCD.234"), None);
    }

    #[test]
    fn display_is_a_pure_function_of_the_stored_form() {
        assert_eq!(display("ABCD1234"), "ABCD-1234");
        assert_eq!(normalise(&display("ABCD1234")).unwrap(), "ABCD1234");
        // Never panics on a malformed input, even though callers pass stored
        // (and therefore canonical) codes.
        assert_eq!(display("short"), "short");
    }
}
