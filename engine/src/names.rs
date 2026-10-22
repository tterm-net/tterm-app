//! Names as people give them: of terminals, of the project, of the person.
//! The same rules as tterm-web's core (`accounts.py`).

/// Marks that only steer or hide the text (Unicode's format characters,
/// such as U+202E, which turns it around, or U+200B, which is not seen),
/// and private-use characters: left out of names.
pub(crate) fn hidden(c: char) -> bool {
    matches!(c as u32,
        0x00AD | 0x0600..=0x0605 | 0x061C | 0x06DD | 0x070F | 0x0890..=0x0891 | 0x08E2
        | 0x180E | 0x200B..=0x200F | 0x202A..=0x202E | 0x2060..=0x2064 | 0x2066..=0x206F
        | 0xFEFF | 0xFFF9..=0xFFFB | 0x110BD | 0x110CD | 0x13430..=0x1343F
        | 0x1BCA0..=0x1BCA3 | 0x1D173..=0x1D17A | 0xE0001 | 0xE0020..=0xE007F
        | 0xE000..=0xF8FF | 0xF0000..=0xFFFFD | 0x100000..=0x10FFFD)
}

/// A name as lists show it: what prints, on one line. Controls and line
/// breaks become spaces; hidden marks are left out; spaces tidied.
///
/// One difference from the core, met on random names: a character Unicode
/// has not assigned yet stays here, while Python leaves it out (it is not
/// printable to Python). Which ones are assigned depends on the version of
/// Unicode either side knows, so the two could not agree on all of them.
pub fn one_line(text: &str) -> String {
    let shown: String = text
        .chars()
        .filter_map(|c| {
            if c.is_control() || c.is_whitespace() || c == '\u{2028}' || c == '\u{2029}' {
                Some(' ')
            } else if hidden(c) {
                None
            } else {
                Some(c)
            }
        })
        .collect();
    shown.split_whitespace().collect::<Vec<_>>().join(" ")
}

pub fn first_name(name: &str) -> String {
    name.split_whitespace().next().unwrap_or(name).to_string()
}

/// Two letters for the avatar: first and last word, so that a middle name
/// does not push the surname out. A single word gives a single letter.
pub fn initials(name: &str) -> String {
    let words: Vec<&str> = name
        .split(|c: char| !(c.is_alphanumeric()))
        .filter(|w| !w.is_empty())
        .collect();
    match words.len() {
        0 => "?".to_string(),
        1 => first_upper(words[0]),
        _ => format!("{}{}", first_upper(words[0]), first_upper(words[words.len() - 1])),
    }
}

fn first_upper(word: &str) -> String {
    word.chars().next().map(|c| c.to_uppercase().collect()).unwrap_or_default()
}

/// One to four letters or digits.
pub fn valid_code(code: &str) -> bool {
    let n = code.chars().count();
    (1..=4).contains(&n) && code.chars().all(char::is_alphanumeric)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert_eq!(one_line("  web\u{202e}  logs\n"), "web logs");
        assert_eq!(one_line("a\u{200b}b"), "ab");
        assert_eq!(initials("Denis Gerasimenko"), "DG");
        assert_eq!(initials("Denis Ivanovich Gerasimenko"), "DG");
        assert_eq!(initials("denis"), "D");
        assert_eq!(initials("Денис Герасименко"), "ДГ");
        assert_eq!(initials("__"), "?");
        assert_eq!(first_name("Denis Gerasimenko"), "Denis");
        assert!(valid_code("P"));
        assert!(valid_code("CX2"));
        assert!(!valid_code("ABCDE"));
        assert!(!valid_code("C_X"));
    }
}
