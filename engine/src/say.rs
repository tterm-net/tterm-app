//! The words of tTerm for Mac in the language shown (from 0.6.0): tTerm's
//! menu, the icon in the menu bar, the questions it asks, and what Settings'
//! Updates says of a new version. The page of tTerm Web has its own words
//! (tterm-web, web/src/i18n); these are the app's, in files of the same
//! kind, one a language in engine/i18n, built into the program: `key =
//! text` a line, {name} a value, "one: … | other: …" a form for each plural
//! of the language (Unicode CLDR, as the site and the page count). A key a
//! language lacks is said in English.
//!
//! Which language: the one chosen in the app (Settings::language; signed in,
//! the account's, which the engine keeps here too), else the system's when
//! it is one of the twelve, else English (Engine::language_now). Nothing
//! here is global: each word is said in the language it is asked in.

use std::collections::HashMap;
use std::fmt;
use std::sync::OnceLock;

/// The twelve of the site and the page, in the order of their menus.
pub const LANGUAGES: [&str; 12] = ["en", "de", "es", "fr", "it", "pl", "pt-BR", "tr", "ru", "ja", "ko", "zh-CN"];

const FILES: [(&str, &str); 12] = [
    ("en", include_str!("../i18n/en.txt")),
    ("de", include_str!("../i18n/de.txt")),
    ("es", include_str!("../i18n/es.txt")),
    ("fr", include_str!("../i18n/fr.txt")),
    ("it", include_str!("../i18n/it.txt")),
    ("pl", include_str!("../i18n/pl.txt")),
    ("pt-BR", include_str!("../i18n/pt-BR.txt")),
    ("tr", include_str!("../i18n/tr.txt")),
    ("ru", include_str!("../i18n/ru.txt")),
    ("ja", include_str!("../i18n/ja.txt")),
    ("ko", include_str!("../i18n/ko.txt")),
    ("zh-CN", include_str!("../i18n/zh-CN.txt")),
];

/// One of the twelve, as it is spelled there; None for any other.
pub fn language(code: &str) -> Option<&'static str> {
    LANGUAGES.iter().copied().find(|l| *l == code)
}

/// A language file read: `key = text` a line, `#` a comment; `\n` in a
/// text is a line break, `\\` a backslash.
pub fn parse(text: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for line in text.lines() {
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = match line.split_once(" =") {
            Some((key, rest)) => (key, rest.strip_prefix(' ').unwrap_or(rest)),
            None => continue,
        };
        if key.is_empty() || !key.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_.-".contains(&b)) {
            continue;
        }
        out.insert(key.to_string(), unescape(value));
    }
    out
}

fn unescape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.peek() {
                Some('n') => {
                    chars.next();
                    out.push('\n');
                    continue;
                }
                Some('\\') => {
                    chars.next();
                    out.push('\\');
                    continue;
                }
                _ => {}
            }
        }
        out.push(c);
    }
    out
}

fn tables() -> &'static HashMap<&'static str, HashMap<String, String>> {
    static TABLES: OnceLock<HashMap<&'static str, HashMap<String, String>>> = OnceLock::new();
    TABLES.get_or_init(|| FILES.iter().map(|(code, text)| (*code, parse(text))).collect())
}

/// The plural form of n in a language, by the rules of Unicode CLDR for
/// whole numbers, as the site counts (sitelib.py, plural).
pub fn plural(lang: &str, n: u64) -> &'static str {
    match lang {
        "ja" | "ko" | "zh-CN" => "other",
        "ru" if n % 10 == 1 && n % 100 != 11 => "one",
        "ru" | "pl" if (2..=4).contains(&(n % 10)) && !(12..=14).contains(&(n % 100)) => "few",
        "ru" => "many",
        "pl" if n == 1 => "one",
        "pl" => "many",
        "fr" | "pt-BR" => {
            if n <= 1 {
                "one"
            } else {
                "other"
            }
        }
        _ => {
            if n == 1 {
                "one"
            } else {
                "other"
            }
        }
    }
}

const FORMS: [&str; 6] = ["zero", "one", "two", "few", "many", "other"];

/// "one: {n} terminal | other: {n} terminals" as its forms; None for a
/// text without them.
pub fn forms_of(text: &str) -> Option<Vec<(&str, &str)>> {
    let mut forms = Vec::new();
    for part in text.split(" | ") {
        let (name, rest) = part.split_once(": ")?;
        if !FORMS.contains(&name) {
            return None;
        }
        forms.push((name, rest));
    }
    Some(forms)
}

/// Something to say: a key of the language files with its values, said
/// in whichever language it is asked in. What the updater keeps to show
/// later (update.rs) is kept so, not as words of one language.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Said {
    pub key: &'static str,
    pub values: Vec<(&'static str, String)>,
}

impl Said {
    pub const fn new(key: &'static str) -> Said {
        Said { key, values: Vec::new() }
    }

    /// With the value {name}.
    pub fn with(mut self, name: &'static str, value: impl Into<String>) -> Said {
        self.values.push((name, value.into()));
        self
    }

    /// Counting n: the form of the language for n, and {n}.
    pub fn count(self, n: u64) -> Said {
        self.with("n", n.to_string())
    }

    /// The words in a language (one of the twelve; any other is English).
    pub fn said_in(&self, lang: &str) -> String {
        let english = &tables()["en"];
        let text = tables().get(lang).and_then(|t| t.get(self.key)).or_else(|| english.get(self.key));
        let Some(text) = text else { return self.key.to_string() };
        let n = self.values.iter().find(|(name, _)| *name == "n").and_then(|(_, v)| v.parse::<u64>().ok());
        let chosen = match forms_of(text) {
            Some(forms) => {
                let form = n.map(|n| plural(if tables().contains_key(lang) { lang } else { "en" }, n)).unwrap_or("other");
                let pick = |name: &str| forms.iter().find(|(f, _)| *f == name).map(|(_, t)| *t);
                pick(form).or_else(|| pick("other")).or_else(|| pick("many")).unwrap_or(forms[0].1).to_string()
            }
            None => text.clone(),
        };
        fill(&chosen, &self.values)
    }

    /// The words in English: for the log.
    pub fn english(&self) -> String {
        self.said_in("en")
    }
}

/// English, where a Said is written out without a language: a log line, a
/// check.
impl fmt::Display for Said {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.english())
    }
}

/// The words of `key` in `lang`, with no values.
pub fn say(lang: &str, key: &'static str) -> String {
    Said::new(key).said_in(lang)
}

fn fill(text: &str, values: &[(&'static str, String)]) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find('{') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        match after.find('}') {
            Some(end) if after[..end].chars().all(|c| c.is_ascii_alphanumeric() || c == '_') && !after[..end].is_empty() => {
                let name = &after[..end];
                match values.iter().find(|(n, _)| *n == name) {
                    Some((_, value)) => out.push_str(value),
                    None => out.push_str(&rest[start..start + end + 2]),
                }
                rest = &after[end + 1..];
            }
            _ => {
                out.push('{');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// The first of the twelve among the languages a person prefers, as the
/// page picks among the browser's (web/src/i18n.ts, pickLanguage): de-AT
/// is Deutsch, pt-PT Português, Chinese in simplified characters 简体中文,
/// in traditional ones none of them, and the next is looked at.
pub fn pick<S: AsRef<str>>(tags: &[S]) -> Option<&'static str> {
    for tag in tags {
        let tag = tag.as_ref().to_ascii_lowercase().replace('_', "-");
        // "en-US.UTF-8", "C", "POSIX": what Linux says.
        let tag = tag.split(['.', '@']).next().unwrap_or("");
        let base = tag.split('-').next().unwrap_or("");
        if base == "zh" {
            if tag.split('-').skip(1).any(|p| matches!(p, "hant" | "tw" | "hk" | "mo")) {
                continue;
            }
            return Some("zh-CN");
        }
        if base == "pt" {
            return Some("pt-BR");
        }
        if let Some(found) = LANGUAGES.iter().copied().find(|l| *l == base) {
            return Some(found);
        }
    }
    None
}

/// The system's language, when it is one of the twelve: on a Mac the first
/// of System Settings' preferred languages (tTerm's own, if one is set for
/// it there) that is.
pub fn system() -> Option<&'static str> {
    let tags: Vec<String> = sys_locale::get_locales().collect();
    pick(&tags)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_as_the_site_does() {
        assert_eq!([1, 2, 5, 21, 22, 25, 11, 12, 111].map(|n| plural("ru", n)), ["one", "few", "many", "one", "few", "many", "many", "many", "many"]);
        assert_eq!([1, 2, 5, 21, 22, 12].map(|n| plural("pl", n)), ["one", "few", "many", "many", "few", "many"]);
        assert_eq!([0, 1, 2].map(|n| plural("fr", n)), ["one", "one", "other"]);
        assert_eq!([0, 1, 2].map(|n| plural("pt-BR", n)), ["one", "one", "other"]);
        assert_eq!([0, 1, 2].map(|n| plural("de", n)), ["other", "one", "other"]);
        assert_eq!(plural("ja", 1), "other");
    }

    #[test]
    fn picks_among_the_twelve() {
        assert_eq!(pick(&["de-AT"]), Some("de"));
        assert_eq!(pick(&["pt-PT"]), Some("pt-BR"));
        assert_eq!(pick(&["zh-Hans-CN"]), Some("zh-CN"));
        assert_eq!(pick(&["zh-Hant-TW", "ja-JP"]), Some("ja"));
        assert_eq!(pick(&["zh_TW", "uk-UA"]), None);
        assert_eq!(pick(&["en_GB.UTF-8"]), Some("en"));
        assert_eq!(pick(&["C", "POSIX"]), None);
        assert_eq!(pick(&["ru"]), Some("ru"));
    }

    #[test]
    fn says_with_values_and_forms() {
        let file = parse("a = Hello, {name}!\nb = one: {n} terminal | other: {n} terminals\n# c = no\nd = {missing} \\n {x\ne =\n");
        assert_eq!(file["a"], "Hello, {name}!");
        assert_eq!(file["d"], "{missing} \n {x");
        assert_eq!(file["e"], "");
        assert!(!file.contains_key("# c"));
        assert_eq!(fill(&file["a"], &[("name", "Denis".into())]), "Hello, Denis!");
        assert_eq!(fill(&file["d"], &[]), "{missing} \n {x");
        assert_eq!(forms_of(&file["b"]).unwrap(), vec![("one", "{n} terminal"), ("other", "{n} terminals")]);
        assert_eq!(forms_of("Run | stop: now"), None);
    }

    /// Every language has every key English has, with English's values,
    /// and the forms of its own where English counts; no key English lacks.
    #[test]
    fn every_language_has_every_word() {
        let english = &tables()["en"];
        assert!(english.len() > 20, "{} keys in English", english.len());
        let places = |text: &str| -> Vec<String> {
            let mut found: Vec<String> = text.split('{').skip(1).filter_map(|p| p.split_once('}').map(|(n, _)| n.to_string())).filter(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')).collect();
            found.sort();
            found.dedup();
            found
        };
        let wanted_forms = |lang: &str| -> Vec<&str> {
            match lang {
                "ru" | "pl" => vec!["one", "few", "many"],
                "ja" | "ko" | "zh-CN" => vec!["other"],
                _ => vec!["one", "other"],
            }
        };
        for (code, _) in FILES {
            let own = &tables()[code];
            let mut missing: Vec<&String> = english.keys().filter(|k| !own.contains_key(*k)).collect();
            missing.sort();
            assert!(missing.is_empty(), "{code} lacks {missing:?}");
            let extra: Vec<&String> = own.keys().filter(|k| !english.contains_key(*k)).collect();
            assert!(extra.is_empty(), "{code} has {extra:?}, which English has not");
            for (key, source) in english {
                let text = &own[key];
                assert!(source.trim().is_empty() || !text.trim().is_empty(), "{code}: {key} is empty");
                match (forms_of(source), forms_of(text)) {
                    (Some(theirs), Some(ours)) => {
                        let mut names: Vec<&str> = ours.iter().map(|(f, _)| *f).collect();
                        names.sort();
                        let mut wanted = wanted_forms(code);
                        wanted.sort();
                        assert_eq!(names, wanted, "{code}: {key} has the forms {names:?}");
                        let need = places(theirs.iter().find(|(f, _)| *f == "other").map(|(_, t)| *t).unwrap_or(""));
                        for (form, part) in ours {
                            let got = places(part);
                            let may_drop_n = form == "one" && matches!(code, "en" | "de" | "es" | "it" | "tr");
                            let need: Vec<&String> = need.iter().filter(|p| !(may_drop_n && p.as_str() == "n")).collect();
                            assert!(need.iter().all(|p| got.contains(p)) && got.iter().all(|p| places(source).contains(p) || p == "n"), "{code}: {key} ({form}) has {got:?}, English {need:?}");
                        }
                    }
                    (None, None) => assert_eq!(places(text), places(source), "{code}: {key}"),
                    _ => panic!("{code}: {key} counts in one language and not in the other"),
                }
            }
        }
    }
}
