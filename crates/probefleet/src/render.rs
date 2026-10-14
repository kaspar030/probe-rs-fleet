//! Shared cell renderers for the CLI's tables.
//!
//! Small on purpose: the point is that every surface which prints a tag set
//! prints it *the same way*, from one place.

/// Render a tag set for a table cell.
///
/// One helper, three call sites (`ctl list`, `ctl nodes`, `node board list`),
/// deliberately: tag *inheritance* (issue #514) will want an inherited tag
/// rendered distinguishably from a directly-declared one (e.g. `desk*`), and
/// that must be one edit here rather than three inlined `join(",")` calls that
/// have to be found first.
///
/// An empty set renders as the **empty string**, never a placeholder word:
/// `none` and `-` are legal tag values, so a placeholder cell would be
/// ambiguous between "no tags" and "one tag, spelled `none`".
pub(crate) fn tags_cell(tags: &[String]) -> String {
    tags.join(",")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owned(tags: &[&str]) -> Vec<String> {
        tags.iter().map(|t| (*t).to_owned()).collect()
    }

    #[test]
    fn no_tags_is_an_empty_cell_not_a_placeholder() {
        assert_eq!(tags_cell(&[]), "");
    }

    #[test]
    fn tags_are_comma_joined() {
        assert_eq!(tags_cell(&owned(&["nrf52", "desk"])), "nrf52,desk");
    }

    /// The reason the empty case is an empty cell: a board really can carry a
    /// tag spelled `none`, and it must not be confused with carrying nothing.
    #[test]
    fn a_literal_none_tag_is_distinguishable_from_no_tags() {
        assert_eq!(tags_cell(&owned(&["none"])), "none");
        assert_ne!(tags_cell(&owned(&["none"])), tags_cell(&[]));
    }
}
