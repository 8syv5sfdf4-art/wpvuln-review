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

use crate::db::{PullEvent, PullOptions, PullStatus};
use crate::error::{Error, Result};
use crate::inventory::{Component, Inventory, Kind};
use crate::scanner::ComponentType;

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
    /// Slug the component is installed under
    pub installed: String,
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
                installed: c.slug.clone(),
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
            installed: c.slug.clone(),
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

/// Everything to look up for an inventory: each plugin, unloaded plugin
/// and theme, resolved through `aliases`. Must-use plugins and drop-ins
/// are never looked up. Identical lookups (say, a plugin covered by a
/// theme that is checked anyway) appear once, under the first component
/// that needs them.
pub fn lookups(inv: &Inventory, aliases: &Aliases) -> Vec<Lookup> {
    let mut out: Vec<Lookup> = Vec::new();
    for c in &inv.components {
        let Some(l) = aliases.resolve(inv, c) else {
            continue;
        };
        let same = |o: &Lookup| o.kind == l.kind && o.slug == l.slug && o.version == l.version;
        if !out.iter().any(same) {
            out.push(l);
        }
    }
    out
}

/// One possible lookup slug for an installed component
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// Proposed target
    pub target: Target,
    /// Why it was proposed
    pub reasons: Vec<String>,
    /// What the database says about it, when one was consulted
    pub known: Option<Known>,
}

/// Proposed alias for one installed plugin or theme
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Suggestion {
    /// Table the alias belongs in ([`Kind::Plugin`] or [`Kind::Theme`])
    pub table: Kind,
    /// Installed slug (the alias key)
    pub slug: String,
    /// Human description: name, version and where it was found
    pub label: String,
    /// What the database says about the installed slug itself
    pub own: Option<Known>,
    /// Candidates, most likely first
    pub candidates: Vec<Candidate>,
    /// Index of the candidate confirmed as tracked, if any
    pub chosen: Option<usize>,
    /// Parent theme, for a child theme
    pub parent: Option<String>,
}

pub use crate::db::Known;

/// Suffixes that usually mark a premium edition or a copy of a plugin
const SUFFIXES: [&str; 6] = ["--", "-old", "-main", "-master", "-premium", "-pro"];

/// One renaming step towards a wordpress.org slug, with its reason
/// wordpress.org slugs a folder name may stand for, closest first, each
/// with how it was derived: lowercased, then `-premium`, `-pro`, `-old`,
/// `-main`, `-master`, `--` and trailing digits stripped one at a time
pub fn name_variants(slug: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut current = slug.to_ascii_lowercase();
    let mut steps = Vec::new();
    if current != slug {
        steps.push("lowercased".to_string());
        out.push((current.clone(), steps.join(", ")));
    }
    while let Some((next, why)) = strip_once(&current) {
        steps.push(why);
        out.push((next.clone(), steps.join(", ")));
        current = next;
    }
    out
}

fn strip_once(slug: &str) -> Option<(String, String)> {
    for suffix in SUFFIXES {
        if let Some(rest) = slug.strip_suffix(suffix)
            && !rest.is_empty()
        {
            return Some((rest.to_string(), format!("dropped \"{suffix}\"")));
        }
    }
    let rest = slug.trim_end_matches(|c: char| c.is_ascii_digit());
    let rest = rest.trim_end_matches(['-', '_']);
    if rest.len() < slug.len() && rest.chars().any(|c| c.is_ascii_alphabetic()) {
        return Some((rest.to_string(), "dropped trailing digits".to_string()));
    }
    None
}

/// `wordpress.org/plugins/<slug>` (or `/themes/`) in a header URI
fn wporg_slug(uri: &str, kind: Kind) -> Option<String> {
    let dir = if kind == Kind::Theme {
        "wordpress.org/themes/"
    } else {
        "wordpress.org/plugins/"
    };
    let rest = &uri[uri.find(dir)? + dir.len()..];
    let slug = rest.split(['/', '?', '#']).next()?.to_ascii_lowercase();
    crate::db::is_safe_key(&slug).then_some(slug)
}

/// Candidate lookup slugs for one component, most likely first
pub fn candidates(inv: &Inventory, c: &Component) -> Vec<Candidate> {
    let own = if c.kind == Kind::Theme {
        Kind::Theme
    } else {
        Kind::Plugin
    };
    let mut out: Vec<Candidate> = Vec::new();
    let mut add = |kind: Kind, slug: String, reason: String| {
        if !crate::db::is_safe_key(&slug) || (kind == own && slug == c.slug) {
            return;
        }
        match out
            .iter_mut()
            .find(|x| x.target.kind == kind && x.target.slug == slug)
        {
            Some(x) => x.reasons.push(reason),
            None => out.push(Candidate {
                target: Target { kind, slug },
                reasons: vec![reason],
                known: None,
            }),
        }
    };

    for (header, uri) in [("Plugin/Theme URI", &c.uri), ("Update URI", &c.update_uri)] {
        if let Some(slug) = uri.as_deref().and_then(|u| wporg_slug(u, own)) {
            add(own, slug, format!("{header} points to wordpress.org"));
        }
    }
    for (variant, why) in name_variants(&c.slug) {
        add(own, variant, why);
    }
    if let Some(td) = c.text_domain.as_deref() {
        add(
            own,
            td.to_ascii_lowercase(),
            "Text Domain header".to_string(),
        );
    }
    if own == Kind::Plugin {
        for theme in inv.components.iter().filter(|t| t.kind == Kind::Theme) {
            let named = c.slug.starts_with(&format!("{}-", theme.slug))
                || c.text_domain.as_deref() == Some(theme.slug.as_str());
            if named {
                add(
                    Kind::Theme,
                    theme.slug.clone(),
                    format!(
                        "named after the installed theme \"{}\"; such plugins usually ship with \
                         the theme and share its version",
                        theme.slug
                    ),
                );
            }
        }
    }
    out
}

/// Answers what a database knows about a plugin or theme slug
pub type KnownFn<'a> = &'a dyn Fn(Kind, &str) -> Known;

/// Proposals for every plugin and theme without an alias yet. With
/// `known`, candidates are checked against a database: components whose
/// own slug is tracked are skipped, and the first tracked candidate is
/// chosen.
pub fn suggest(inv: &Inventory, existing: &Aliases, known: Option<KnownFn>) -> Vec<Suggestion> {
    let mut out: Vec<Suggestion> = Vec::new();
    for c in &inv.components {
        let table = match c.kind {
            Kind::Plugin | Kind::Unloaded => Kind::Plugin,
            Kind::Theme => Kind::Theme,
            Kind::MuPlugin | Kind::Dropin => continue,
        };
        let where_ = if c.kind == Kind::Unloaded {
            format!("{}, not loaded by WordPress", c.main_file)
        } else {
            c.main_file.clone()
        };
        let label = format!(
            "{} {} ({where_})",
            c.name,
            c.version.as_deref().unwrap_or("(no version)")
        );
        // A live plugin and an unloaded copy can share a folder name
        if let Some(s) = out
            .iter_mut()
            .find(|s| s.table == table && s.slug == c.slug)
        {
            s.label = format!("{}; also {label}", s.label);
            continue;
        }
        if existing.target(c.kind, &c.slug).is_some() {
            continue;
        }
        let own = known.map(|k| k(table, &c.slug));
        if matches!(own, Some(Known::Tracked(_))) {
            continue;
        }
        let mut candidates = candidates(inv, c);
        if let Some(k) = known {
            for cand in &mut candidates {
                cand.known = Some(k(cand.target.kind, &cand.target.slug));
            }
        }
        if candidates.is_empty() && known.is_none() {
            continue;
        }
        let chosen = candidates
            .iter()
            .position(|x| matches!(x.known, Some(Known::Tracked(_))));
        out.push(Suggestion {
            table,
            slug: c.slug.clone(),
            label,
            own,
            candidates,
            chosen,
            parent: c.parent.clone(),
        });
    }
    out
}

/// Every slug [`suggest`] would ask about: each unaliased plugin's and
/// theme's own slug plus all its candidates, without duplicates
pub fn lookups_needed(inv: &Inventory, existing: &Aliases) -> Vec<(Kind, String)> {
    let mut out: Vec<(Kind, String)> = Vec::new();
    for c in &inv.components {
        let own = match c.kind {
            Kind::Plugin | Kind::Unloaded => Kind::Plugin,
            Kind::Theme => Kind::Theme,
            Kind::MuPlugin | Kind::Dropin => continue,
        };
        if existing.target(c.kind, &c.slug).is_some() {
            continue;
        }
        let wanted = std::iter::once((own, c.slug.clone())).chain(
            candidates(inv, c)
                .into_iter()
                .map(|x| (x.target.kind, x.target.slug)),
        );
        for item in wanted {
            if crate::db::is_safe_key(&item.1) && !out.contains(&item) {
                out.push(item);
            }
        }
    }
    out
}

fn component_type(kind: Kind) -> ComponentType {
    if kind == Kind::Theme {
        ComponentType::Theme
    } else {
        ComponentType::Plugin
    }
}

/// Like [`suggest`] with a database, but slugs the local database `db`
/// lacks (or all of them, without one) are fetched from the API first.
/// They go into a temporary directory that is removed afterwards, so the
/// local database is never changed. Returns the suggestions and the
/// lookups that failed (those read as [`Known::Missing`]).
pub async fn suggest_online(
    inv: &Inventory,
    existing: &Aliases,
    db: Option<&Path>,
    opts: &PullOptions,
) -> Result<(Vec<Suggestion>, Vec<String>)> {
    let local = |kind: Kind, slug: &str| {
        db.map_or(Known::Missing, |d| {
            crate::db::known(d, component_type(kind), slug)
        })
    };
    let fetch: Vec<(ComponentType, String)> = lookups_needed(inv, existing)
        .into_iter()
        .filter(|(kind, slug)| local(*kind, slug) == Known::Missing)
        .map(|(kind, slug)| (component_type(kind), slug))
        .collect();
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let tmp = std::env::temp_dir().join(format!("wpvuln-suggest-{}-{stamp}", std::process::id()));
    let mut failed = Vec::new();
    let pulled = crate::db::pull(&tmp, &fetch, opts, |e: &PullEvent| {
        if let PullStatus::Failed(why) = &e.status {
            failed.push(format!("{}: {why}", e.key));
        }
    })
    .await;
    let lookup = |kind: Kind, slug: &str| match local(kind, slug) {
        Known::Missing => crate::db::known(&tmp, component_type(kind), slug),
        known => known,
    };
    let out = pulled.map(|_| suggest(inv, existing, Some(&lookup)));
    let _ = std::fs::remove_dir_all(&tmp);
    Ok((out?, failed))
}

fn describe(known: Option<Known>) -> String {
    match known {
        Some(Known::Tracked(0)) => "tracked, no known vulnerabilities".to_string(),
        Some(Known::Tracked(1)) => "tracked, 1 record".to_string(),
        Some(Known::Tracked(n)) => format!("tracked, {n} records"),
        Some(Known::Untracked) => "not tracked".to_string(),
        Some(Known::Missing) => "not in the database".to_string(),
        None => "unconfirmed".to_string(),
    }
}

fn toml_value(table: Kind, target: &Target) -> String {
    if target.kind == table {
        format!("\"{}\"", target.slug)
    } else {
        format!("{{ {} = \"{}\" }}", kind_name(target.kind), target.slug)
    }
}

/// Suggestions as a commented TOML file. Only confirmed candidates are
/// active lines; everything else is commented out for review.
pub fn render(suggestions: &[Suggestion], checked_against: &str) -> String {
    let mut out = String::from(
        "# Alias suggestions. Nothing here is applied automatically: review each entry,\n\
         # then copy the lines you agree with into aliases.toml.\n\
         # Matches found through an alias are labelled \"alias\" in reports, because\n\
         # premium editions may number their versions differently from the free plugin.\n",
    );
    out.push_str(&format!(
        "# Candidates checked against: {checked_against}\n"
    ));
    for table in [Kind::Plugin, Kind::Theme] {
        let rows: Vec<&Suggestion> = suggestions.iter().filter(|s| s.table == table).collect();
        if rows.is_empty() {
            continue;
        }
        out.push_str(&format!("\n[{}]\n", kind_name(table)));
        for s in rows {
            out.push_str(&format!("\n# {}: {}\n", s.slug, s.label));
            if let Some(own) = s.own {
                out.push_str(&format!("#   own slug: {}\n", describe(Some(own))));
            }
            if let (true, Some(parent)) = (s.candidates.is_empty(), &s.parent) {
                out.push_str(&format!(
                    "#   child theme of \"{parent}\": it holds this site's own changes, which no\n\
                     #   database covers, so review it by hand. The parent is checked on its own.\n"
                ));
                continue;
            }
            if s.candidates.is_empty() {
                out.push_str(
                    "#   no candidate slug found. Probably custom or marketplace code that no\n\
                     #   database covers; it stays \"not checked\", so review it by hand.\n",
                );
                continue;
            }
            for c in &s.candidates {
                out.push_str(&format!(
                    "#   {} = {}: {}\n",
                    s.slug,
                    toml_value(table, &c.target),
                    [describe(c.known)]
                        .into_iter()
                        .chain(c.reasons.iter().cloned())
                        .collect::<Vec<_>>()
                        .join("; ")
                ));
            }
            let missing = s
                .candidates
                .iter()
                .find(|c| c.known == Some(Known::Missing));
            match (s.chosen, missing) {
                (Some(i), _) => out.push_str(&format!(
                    "\"{}\" = {}\n",
                    s.slug,
                    toml_value(table, &s.candidates[i].target)
                )),
                (None, Some(m)) => out.push_str(&format!(
                    "#   not in the database yet, so unconfirmed: rerun with --online, or\n\
                     #   `db pull -p {}` first.\n# \"{}\" = {}\n",
                    m.target.slug,
                    s.slug,
                    toml_value(table, &m.target)
                )),
                (None, None) if s.candidates.iter().any(|c| c.known.is_some()) => out.push_str(
                    "#   none of these is tracked, so there is nothing to map to; it stays\n\
                     #   \"not checked\".\n",
                ),
                (None, None) => out.push_str(&format!(
                    "# \"{}\" = {}\n",
                    s.slug,
                    toml_value(table, &s.candidates[0].target)
                )),
            }
        }
    }
    out
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
