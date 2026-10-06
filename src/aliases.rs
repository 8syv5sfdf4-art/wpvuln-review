//! Slug aliases: installed folder name -> slug to look up
//!
//! Vulnerability data is keyed by wordpress.org slug, but an inventory holds
//! folder names. They differ for premium editions, renamed copies and
//! plugins that ship with a theme. An aliases file maps one to the other.
//! It is written by hand; `aliases suggest` only proposes entries.
//!
//! ```toml
//! [plugin]
//! "chaty-pro2" = "chaty"
//! "yith-woocommerce-product-bundles-premium" = "yith-woocommerce-product-bundles"
//! "woodmart-plus" = { theme = "woodmart" }   # covered by the theme's own check
//!
//! [theme]
//! "flatsome-old" = "flatsome"
//! ```
//!
//! A match found through an alias is labelled [`MatchedVia::Alias`]:
//! premium editions do not always number their versions like the free one.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::inventory::{Component, Inventory, Kind};

/// Where an alias points
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// Look up as a plugin ([`Kind::Plugin`]) or a theme ([`Kind::Theme`])
    pub kind: Kind,
    /// wordpress.org slug to look up
    pub slug: String,
}

/// Parsed aliases file
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Aliases {
    /// `[plugin]` table: installed plugin slug -> target
    pub plugin: BTreeMap<String, Target>,
    /// `[theme]` table: installed theme slug -> target
    pub theme: BTreeMap<String, Target>,
}

/// How a component was matched to vulnerability data
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MatchedVia {
    /// Looked up under its own slug
    Slug,
    /// Looked up through an alias; findings may need confirmation
    Alias,
}

/// What to look up for one installed component
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lookup {
    /// Plugin or theme
    pub kind: Kind,
    /// Slug to look up
    pub slug: String,
    /// Version to compare; for a cross-type alias, the target's version
    pub version: Option<String>,
    /// Own slug or alias
    pub matched_via: MatchedVia,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFile {
    #[serde(default)]
    plugin: BTreeMap<String, toml::Value>,
    #[serde(default)]
    theme: BTreeMap<String, toml::Value>,
}

impl Aliases {
    /// Read and validate an aliases file
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| Error::Aliases(format!("{}: {e}", path.display())))?;
        Self::parse(&text).map_err(|e| match e {
            Error::Aliases(msg) => Error::Aliases(format!("{}: {msg}", path.display())),
            other => other,
        })
    }

    /// Parse and validate aliases from TOML text
    pub fn parse(text: &str) -> Result<Self> {
        let raw: RawFile = toml::from_str(text).map_err(|e| Error::Aliases(e.to_string()))?;
        Ok(Self {
            plugin: convert(raw.plugin, Kind::Plugin, "plugin")?,
            theme: convert(raw.theme, Kind::Theme, "theme")?,
        })
    }

    /// The alias for an installed component, if any. Must-use plugins and
    /// drop-ins are never looked up, so they have none.
    pub fn target(&self, kind: Kind, slug: &str) -> Option<&Target> {
        match kind {
            Kind::Plugin | Kind::Unloaded => self.plugin.get(slug),
            Kind::Theme => self.theme.get(slug),
            Kind::MuPlugin | Kind::Dropin => None,
        }
    }

    /// What to look up for `c`, or `None` for kinds that are never looked
    /// up (must-use plugins, drop-ins)
    pub fn resolve(&self, inv: &Inventory, c: &Component) -> Option<Lookup> {
        let own = match c.kind {
            Kind::Plugin | Kind::Unloaded => Kind::Plugin,
            Kind::Theme => Kind::Theme,
            Kind::MuPlugin | Kind::Dropin => return None,
        };
        let Some(target) = self.target(c.kind, &c.slug) else {
            return Some(Lookup {
                kind: own,
                slug: c.slug.clone(),
                version: c.version.clone(),
                matched_via: MatchedVia::Slug,
            });
        };
        let version = if target.kind == own {
            c.version.clone()
        } else {
            // Shipped with another component: its version is what counts
            installed(inv, target).and_then(|t| t.version.clone())
        };
        Some(Lookup {
            kind: target.kind,
            slug: target.slug.clone(),
            version,
            matched_via: MatchedVia::Alias,
        })
    }

    /// Record each component's alias in the inventory (`lookup_slug`, and
    /// `lookup_type` for a cross-type alias) and add [`Aliases::check`]
    /// warnings, so the inventory alone says what will be looked up
    pub fn apply(&self, inv: &mut Inventory) {
        let mut warnings = self.check(inv);
        for c in &mut inv.components {
            let Some(target) = self.target(c.kind, &c.slug) else {
                continue;
            };
            c.lookup_slug = Some(target.slug.clone());
            let own = if c.kind == Kind::Theme {
                Kind::Theme
            } else {
                Kind::Plugin
            };
            c.lookup_type = (target.kind != own).then_some(target.kind);
        }
        inv.warnings.append(&mut warnings);
    }

    /// Entries that cannot do what they say, as explained warnings
    pub fn check(&self, inv: &Inventory) -> Vec<String> {
        let mut warnings = Vec::new();
        for (table, kinds, entries) in [
            ("plugin", &[Kind::Plugin, Kind::Unloaded][..], &self.plugin),
            ("theme", &[Kind::Theme][..], &self.theme),
        ] {
            for (from, target) in entries {
                let present = inv
                    .components
                    .iter()
                    .any(|c| kinds.contains(&c.kind) && &c.slug == from);
                if !present {
                    warnings.push(format!(
                        "aliases [{table}] \"{from}\": no installed {table} has this slug, so the \
                         alias does nothing. Remove it if the {table} was uninstalled, or fix the \
                         spelling (slugs are folder names and case-sensitive)."
                    ));
                    continue;
                }
                let own = if table == "plugin" {
                    Kind::Plugin
                } else {
                    Kind::Theme
                };
                if target.kind != own && installed(inv, target).is_none() {
                    let what = kind_name(target.kind);
                    warnings.push(format!(
                        "aliases [{table}] \"{from}\" = {{ {what} = \"{}\" }}: no {what} \"{}\" \
                         is installed, so the version of {from} is unknown and it is not \
                         checked. Fix the alias, or check the {what} folder name.",
                        target.slug, target.slug
                    ));
                }
            }
        }
        warnings
    }
}

fn kind_name(kind: Kind) -> &'static str {
    match kind {
        Kind::Theme => "theme",
        _ => "plugin",
    }
}

/// The installed component a cross-type alias points at
fn installed<'a>(inv: &'a Inventory, target: &Target) -> Option<&'a Component> {
    inv.components.iter().find(|c| {
        c.slug == target.slug
            && match target.kind {
                Kind::Theme => c.kind == Kind::Theme,
                _ => c.kind == Kind::Plugin,
            }
    })
}

fn convert(
    raw: BTreeMap<String, toml::Value>,
    own: Kind,
    table: &str,
) -> Result<BTreeMap<String, Target>> {
    const FORMS: &str = "use \"slug\", { plugin = \"slug\" } or { theme = \"slug\" }";
    let mut out = BTreeMap::new();
    for (from, to) in raw {
        let bad = |why: &str| Error::Aliases(format!("[{table}] \"{from}\": {why}"));
        let target = match to {
            toml::Value::String(slug) => Target { kind: own, slug },
            toml::Value::Table(t) => {
                let mut keys = t.into_iter();
                let (Some((key, value)), None) = (keys.next(), keys.next()) else {
                    return Err(bad(&format!("{FORMS}, with exactly one key")));
                };
                let kind = match key.as_str() {
                    "plugin" => Kind::Plugin,
                    "theme" => Kind::Theme,
                    other => return Err(bad(&format!("unknown key \"{other}\"; {FORMS}"))),
                };
                let toml::Value::String(slug) = value else {
                    return Err(bad(&format!("the {key} slug must be a string")));
                };
                Target { kind, slug }
            }
            _ => return Err(bad(FORMS)),
        };
        if !crate::db::is_safe_key(&target.slug) {
            return Err(bad(&format!(
                "\"{}\" is not a valid slug (letters, digits, '-', '_' and '.' only)",
                target.slug
            )));
        }
        if target.slug.chars().any(|c| c.is_ascii_uppercase()) {
            return Err(bad(&format!(
                "\"{}\" has uppercase letters, but wordpress.org slugs are lowercase",
                target.slug
            )));
        }
        if target.kind == own && target.slug == from {
            return Err(bad("points at itself"));
        }
        out.insert(from, target);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = r#"
        # premium editions
        [plugin]
        "chaty-pro2" = "chaty"
        "woodmart-plus" = { theme = "woodmart" }
        "RTL-CareUnit" = { plugin = "rtl-careunit" }

        [theme]
        "flatsome-old" = "flatsome"
    "#;

    #[test]
    fn parses_all_forms() {
        let a = Aliases::parse(EXAMPLE).unwrap();
        let t = |kind, slug: &str| Target {
            kind,
            slug: slug.to_string(),
        };
        assert_eq!(a.plugin["chaty-pro2"], t(Kind::Plugin, "chaty"));
        assert_eq!(a.plugin["woodmart-plus"], t(Kind::Theme, "woodmart"));
        assert_eq!(a.plugin["RTL-CareUnit"], t(Kind::Plugin, "rtl-careunit"));
        assert_eq!(a.theme["flatsome-old"], t(Kind::Theme, "flatsome"));
        assert_eq!(Aliases::parse("").unwrap(), Aliases::default());
    }

    #[test]
    fn rejects_mistakes_with_a_reason() {
        let err = |text: &str| Aliases::parse(text).unwrap_err().to_string();
        assert!(err("[plugins]\na = \"b\"").contains("unknown field"));
        assert!(err("[plugin]\na = \"../etc\"").contains("not a valid slug"));
        assert!(err("[plugin]\na = \"Chaty\"").contains("uppercase"));
        assert!(err("[plugin]\na = \"a\"").contains("points at itself"));
        assert!(err("[plugin]\na = { theme = \"x\", plugin = \"y\" }").contains("exactly one key"));
        assert!(
            err("[plugin]\na = { them = \"x\" }").contains("[plugin] \"a\": unknown key \"them\"")
        );
        assert!(err("[plugin]\na = 3").contains("use \"slug\""));
        assert!(err("[plugin\n").contains("line 1"));
    }
}
