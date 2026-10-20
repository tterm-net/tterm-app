//! What the app remembers on this computer, in a small JSON file in its own
//! folder: the ids it gave the person, the project and the machine, and the
//! person's choices (the name, the theme, the project's name, code and
//! color). Written whole, under a new name first, so that a crash never
//! leaves half a file.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use uuid::Uuid;

pub const THEMES: [&str; 3] = ["system", "light", "dark"];
pub const TINTS: [&str; 2] = ["badge", "block"];
pub const COLORS: [&str; 8] = ["violet", "sky", "teal", "pink", "orange", "lime", "indigo", "slate"];

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Settings {
    pub person_id: Uuid,
    pub project_id: Uuid,
    pub machine_id: Uuid,
    /// The person's own name for themselves, once changed on the account
    /// page; until then the account's full name on this computer.
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default = "default_theme")]
    pub theme: String,
    #[serde(default = "default_tint")]
    pub project_tint: String,
    #[serde(default = "default_project")]
    pub project_name: String,
    #[serde(default = "default_code")]
    pub project_code: String,
    #[serde(default = "default_color")]
    pub project_color: String,
    /// When the app first ran here, in milliseconds.
    #[serde(default)]
    pub added_at: i64,
}

fn default_theme() -> String {
    "system".into()
}
fn default_tint() -> String {
    "badge".into()
}
fn default_project() -> String {
    "Personal".into()
}
fn default_code() -> String {
    "P".into()
}
fn default_color() -> String {
    "violet".into()
}

impl Settings {
    fn fresh() -> Self {
        Settings {
            person_id: Uuid::new_v4(),
            project_id: Uuid::new_v4(),
            machine_id: Uuid::new_v4(),
            name: None,
            theme: default_theme(),
            project_tint: default_tint(),
            project_name: default_project(),
            project_code: default_code(),
            project_color: default_color(),
            added_at: crate::terminals::now_ms(),
        }
    }

    pub fn path(dir: &Path) -> PathBuf {
        dir.join("settings.json")
    }

    /// The settings in `dir`, made there on the first run.
    pub fn load(dir: &Path) -> std::io::Result<Self> {
        let path = Self::path(dir);
        if let Ok(text) = std::fs::read_to_string(&path) {
            if let Ok(found) = serde_json::from_str::<Settings>(&text) {
                return Ok(found.tidied());
            }
            // Unreadable: kept aside, and a new one made, rather than an
            // app that does not start.
            let _ = std::fs::rename(&path, dir.join("settings.json.unreadable"));
        }
        let fresh = Self::fresh();
        fresh.save(dir)?;
        Ok(fresh)
    }

    fn tidied(mut self) -> Self {
        if !THEMES.contains(&self.theme.as_str()) {
            self.theme = default_theme();
        }
        if !TINTS.contains(&self.project_tint.as_str()) {
            self.project_tint = default_tint();
        }
        if !COLORS.contains(&self.project_color.as_str()) {
            self.project_color = default_color();
        }
        if !crate::names::valid_code(&self.project_code) {
            self.project_code = default_code();
        }
        if crate::names::one_line(&self.project_name).is_empty() {
            self.project_name = default_project();
        }
        if self.added_at == 0 {
            self.added_at = crate::terminals::now_ms();
        }
        self
    }

    pub fn save(&self, dir: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(dir)?;
        let path = Self::path(dir);
        let tmp = dir.join("settings.json.new");
        let text = serde_json::to_string_pretty(self).map_err(std::io::Error::other)?;
        std::fs::write(&tmp, text)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        }
        std::fs::rename(&tmp, &path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn made_once_and_kept() {
        let dir = std::env::temp_dir().join(format!("tterm-settings-{}", Uuid::new_v4()));
        let first = Settings::load(&dir).unwrap();
        let again = Settings::load(&dir).unwrap();
        assert_eq!(first, again);
        let mut changed = again.clone();
        changed.theme = "light".into();
        changed.save(&dir).unwrap();
        assert_eq!(Settings::load(&dir).unwrap().theme, "light");
        std::fs::write(Settings::path(&dir), "{not json").unwrap();
        let fresh = Settings::load(&dir).unwrap();
        assert_ne!(fresh.machine_id, first.machine_id);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
