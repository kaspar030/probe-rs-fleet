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

/// Lay out a table whose column widths follow the content.
///
/// Each column is as wide as its widest cell (header included, counted in
/// `char`s), columns are separated by two spaces, the last column is never
/// padded, and trailing whitespace is trimmed so an empty last cell leaves
/// none behind. Every line, header included, ends in `\n`.
///
/// Fixed widths were the original layout, and they broke as soon as a value
/// outgrew its slot (a fleet board key is ~70 characters): every column after
/// it shifted right on that row only.
pub(crate) fn table(header: &[&str], rows: &[Vec<String>]) -> String {
    let mut widths: Vec<usize> = header.iter().map(|h| h.chars().count()).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            let w = cell.chars().count();
            match widths.get_mut(i) {
                Some(slot) => *slot = (*slot).max(w),
                None => widths.push(w),
            }
        }
    }
    let mut out = String::new();
    let mut line = |cells: &mut dyn Iterator<Item = &str>| {
        let mut l = String::new();
        for (i, cell) in cells.enumerate() {
            if i > 0 {
                l.push_str("  ");
            }
            l.push_str(cell);
            let pad = widths[i].saturating_sub(cell.chars().count());
            l.extend(std::iter::repeat_n(' ', pad));
        }
        out.push_str(l.trim_end());
        out.push('\n');
    };
    line(&mut header.iter().copied());
    for row in rows {
        line(&mut row.iter().map(String::as_str));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn columns_are_as_wide_as_their_widest_cell() {
        let out = table(
            &["A", "B", "C"],
            &[
                vec![
                    "a-very-long-cell".to_owned(),
                    "x".to_owned(),
                    "1".to_owned(),
                ],
                vec!["s".to_owned(), "yy".to_owned(), "2".to_owned()],
            ],
        );
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines[0], "A                 B   C");
        assert_eq!(lines[1], "a-very-long-cell  x   1");
        assert_eq!(lines[2], "s                 yy  2");
    }

    #[test]
    fn no_trailing_whitespace_for_an_empty_last_cell() {
        let out = table(&["A", "HOLDER"], &[vec!["a".to_owned(), String::new()]]);
        for l in out.lines() {
            assert_eq!(l, l.trim_end(), "{out:?}");
        }
        assert_eq!(out.lines().nth(1), Some("a"));
    }

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
