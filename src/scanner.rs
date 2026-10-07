//! WordPress website scanner
//!
//! Detects WordPress version, plugins, and themes by analyzing the website.

use crate::error::{Error, Result};
use regex::Regex;
use reqwest::Client;
use scraper::{Html, Selector};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::LazyLock;
use std::time::Duration;
use url::Url;

use crate::http::{TIMEOUT_SECS, USER_AGENT};

// Pre-compiled regex patterns for performance
static RE_WP_FEED_VERSION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"wordpress\.org/\?v=([0-9.]+)").unwrap());
static RE_WP_README_VERSION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"Version\s+([0-9.]+)").unwrap());
static RE_THEME_PATH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"/wp-content/themes/([^/]+)/").unwrap());
static RE_PLUGIN_PATH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"/wp-content/plugins/([a-zA-Z0-9_-]+)/").unwrap());

/// Detected component information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentInfo {
    /// Component type
    pub component_type: ComponentType,
    /// Component slug/identifier
    pub slug: String,
    /// Detected version (if found)
    pub version: Option<String>,
    /// Set when `slug` was looked up through an alias: the slug the
    /// component is installed under (its folder name)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installed_as: Option<String>,
}

/// Type of WordPress component
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ComponentType {
    /// WordPress core
    Core,
    /// Plugin
    Plugin,
    /// Theme
    Theme,
}

impl std::fmt::Display for ComponentType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ComponentType::Core => write!(f, "core"),
            ComponentType::Plugin => write!(f, "plugin"),
            ComponentType::Theme => write!(f, "theme"),
        }
    }
}

/// Scan results from analyzing a WordPress site
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    /// Target URL
    pub url: String,
    /// All detected components
    pub components: Vec<ComponentInfo>,
}

impl ScanResult {
    /// Create an empty scan result
    pub fn empty(url: &str) -> Self {
        Self {
            url: url.to_string(),
            components: Vec::new(),
        }
    }

    /// Create from manually specified components
    pub fn from_components(components: Vec<ComponentInfo>) -> Self {
        Self {
            url: String::new(),
            components,
        }
    }

    /// Get WordPress core component
    pub fn core(&self) -> Option<&ComponentInfo> {
        self.components
            .iter()
            .find(|c| c.component_type == ComponentType::Core)
    }

    /// Get all plugins
    pub fn plugins(&self) -> impl Iterator<Item = &ComponentInfo> {
        self.components
            .iter()
            .filter(|c| c.component_type == ComponentType::Plugin)
    }

    /// Get all themes
    pub fn themes(&self) -> impl Iterator<Item = &ComponentInfo> {
        self.components
            .iter()
            .filter(|c| c.component_type == ComponentType::Theme)
    }
}

/// WordPress scanner
pub struct Scanner {
    client: Client,
    base_url: Url,
}

impl Scanner {
    /// Create a new scanner for the given URL
    pub fn new(url: &str) -> Result<Self> {
        let base_url = Url::parse(url).map_err(|e| Error::InvalidUrl(e.to_string()))?;

        let client = Client::builder()
            .user_agent(USER_AGENT)
            .timeout(Duration::from_secs(TIMEOUT_SECS))
            .danger_accept_invalid_certs(false)
            .build()
            .map_err(|e| Error::HttpClient(e.to_string()))?;

        Ok(Self { client, base_url })
    }

    /// Scan the WordPress site
    pub async fn scan(&self) -> Result<ScanResult> {
        // Fetch homepage
        let homepage_html = self.fetch_page(&self.base_url).await?;
        let document = Html::parse_document(&homepage_html);

        let mut components = Vec::new();

        // Detect WordPress version
        if let Some(version) = self.detect_wp_version(&document).await {
            components.push(ComponentInfo {
                component_type: ComponentType::Core,
                slug: "wordpress".to_string(),
                version: Some(version),
                installed_as: None,
            });
        }

        // Detect theme
        if let Some(theme) = self.detect_theme(&document) {
            components.push(theme);
        }

        // Detect plugins
        let plugins = self.detect_plugins(&document);
        components.extend(plugins);

        Ok(ScanResult {
            url: self.base_url.to_string(),
            components,
        })
    }

    /// Fetch a page and return its HTML
    async fn fetch_page(&self, url: &Url) -> Result<String> {
        let response = self
            .client
            .get(url.as_str())
            .send()
            .await
            .map_err(|e| Error::HttpRequest(e.to_string()))?;

        if !response.status().is_success() {
            return Err(Error::HttpStatus(response.status().as_u16()));
        }

        response
            .text()
            .await
            .map_err(|e| Error::HttpRequest(e.to_string()))
    }

    /// Detect WordPress version from various sources
    async fn detect_wp_version(&self, document: &Html) -> Option<String> {
        // Try meta generator tag first
        if let Some(version) = self.detect_version_from_meta(document) {
            return Some(version);
        }

        // Try RSS feed
        if let Some(version) = self.detect_version_from_feed().await {
            return Some(version);
        }

        // Try readme.html
        if let Some(version) = self.detect_version_from_readme().await {
            return Some(version);
        }

        None
    }

    /// Detect version from meta generator tag
    fn detect_version_from_meta(&self, document: &Html) -> Option<String> {
        let selector = Selector::parse("meta[name='generator']").ok()?;

        for element in document.select(&selector) {
            if let Some(content) = element.value().attr("content")
                && content.starts_with("WordPress")
            {
                // Extract version from "WordPress X.Y.Z"
                let version = content.strip_prefix("WordPress ")?.trim();
                if !version.is_empty() {
                    return Some(version.to_string());
                }
            }
        }
        None
    }

    /// Detect version from RSS feed
    async fn detect_version_from_feed(&self) -> Option<String> {
        let feed_url = self.base_url.join("/feed/").ok()?;

        let html = self.fetch_page(&feed_url).await.ok()?;

        // Look for <generator>https://wordpress.org/?v=X.Y.Z</generator>
        let caps = RE_WP_FEED_VERSION.captures(&html)?;
        Some(caps.get(1)?.as_str().to_string())
    }

    /// Detect version from readme.html
    async fn detect_version_from_readme(&self) -> Option<String> {
        let readme_url = self.base_url.join("/readme.html").ok()?;

        let html = self.fetch_page(&readme_url).await.ok()?;

        // Look for "Version X.Y.Z" in readme
        let caps = RE_WP_README_VERSION.captures(&html)?;
        Some(caps.get(1)?.as_str().to_string())
    }

    /// Detect the main theme
    fn detect_theme(&self, document: &Html) -> Option<ComponentInfo> {
        // Look for theme in stylesheet URLs
        let link_selector = Selector::parse("link[rel='stylesheet']").ok()?;

        for element in document.select(&link_selector) {
            if let Some(href) = element.value().attr("href")
                && let Some(info) = self.extract_theme_from_url(href)
            {
                return Some(info);
            }
        }

        // Also check style tags and other sources
        let html = document.html();
        if let Some(caps) = RE_THEME_PATH.captures(&html) {
            let slug = caps.get(1)?.as_str().to_string();
            return Some(ComponentInfo {
                component_type: ComponentType::Theme,
                slug,
                version: None,
                installed_as: None,
            });
        }

        None
    }

    /// Extract theme info from a URL
    fn extract_theme_from_url(&self, url: &str) -> Option<ComponentInfo> {
        // Match /wp-content/themes/theme-name/
        let caps = RE_THEME_PATH.captures(url)?;
        let slug = caps.get(1)?.as_str().to_string();

        let version = extract_version_param(url);

        Some(ComponentInfo {
            component_type: ComponentType::Theme,
            slug,
            version,
            installed_as: None,
        })
    }

    /// Detect plugins from the page
    fn detect_plugins(&self, document: &Html) -> Vec<ComponentInfo> {
        let mut plugin_slugs = HashSet::new();
        let html = document.html();

        // Use pre-compiled regex to find plugin paths
        for caps in RE_PLUGIN_PATH.captures_iter(&html) {
            if let Some(slug) = caps.get(1) {
                let slug_str = slug.as_str().to_string();
                // Skip common non-plugin paths
                if slug_str != "index" && slug_str != "cache" {
                    plugin_slugs.insert(slug_str);
                }
            }
        }

        // Convert to ComponentInfo
        plugin_slugs
            .into_iter()
            .map(|slug| {
                let version = self.find_plugin_version(&html, &slug);
                ComponentInfo {
                    component_type: ComponentType::Plugin,
                    slug,
                    version,
                    installed_as: None,
                }
            })
            .collect()
    }

    /// Find plugin version from HTML
    fn find_plugin_version(&self, html: &str, slug: &str) -> Option<String> {
        // Look for the plugin path and then extract ver= parameter
        // This avoids compiling a new regex for each plugin
        let plugin_path = format!("/wp-content/plugins/{}/", slug);

        // Find all occurrences of this plugin path and check for version
        for (pos, _) in html.match_indices(&plugin_path) {
            // Look ahead in the URL for ver= parameter (within ~200 chars)
            let search_end = (pos + 200).min(html.len());
            let url_slice = &html[pos..search_end];

            // Find the end of this URL (quote or space)
            let url_end = url_slice
                .find(['"', '\'', '>', ' '])
                .unwrap_or(url_slice.len());
            let url = &url_slice[..url_end];

            // Extract version from this URL
            if let Some(version) = extract_version_param(url) {
                return Some(version);
            }
        }
        None
    }
}

/// Version parameter prefix in URLs
const VERSION_PARAM: &str = "ver=";

/// Extract version from URL query parameter (e.g., "?ver=1.2.3")
fn extract_version_param(url: &str) -> Option<String> {
    let v_pos = url.find(VERSION_PARAM)?;
    let v_start = v_pos + VERSION_PARAM.len();
    let v_end = url[v_start..]
        .find(|c: char| !c.is_ascii_alphanumeric() && c != '.')
        .map(|i| v_start + i)
        .unwrap_or(url.len());
    Some(url[v_start..v_end].to_string())
}

/// Parse a component string like "slug:version" or "slug"
pub fn parse_component(s: &str, component_type: ComponentType) -> Result<ComponentInfo> {
    let parts: Vec<&str> = s.split(':').collect();
    match parts.len() {
        1 => Ok(ComponentInfo {
            component_type,
            slug: parts[0].trim().to_string(),
            version: None,
            installed_as: None,
        }),
        2 => Ok(ComponentInfo {
            component_type,
            slug: parts[0].trim().to_string(),
            version: Some(parts[1].trim().to_string()),
            installed_as: None,
        }),
        _ => match component_type {
            ComponentType::Plugin => Err(Error::InvalidPluginFormat(s.to_string())),
            ComponentType::Theme => Err(Error::InvalidThemeFormat(s.to_string())),
            ComponentType::Core => Err(Error::InvalidPluginFormat(s.to_string())),
        },
    }
}

/// Parse a component list, one per line.
///
/// Accepts `slug:version`, `slug version`, `slug,version` or a bare `slug`.
/// Blank lines, `#` comments and a `name,version` header (as printed by
/// `wp plugin list --fields=name,version --format=csv`) are skipped.
pub fn parse_component_list(
    text: &str,
    component_type: ComponentType,
) -> Result<Vec<ComponentInfo>> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() || line.eq_ignore_ascii_case("name,version") {
            continue;
        }
        let normalized = line
            .split(|c: char| c == ',' || c.is_whitespace())
            .filter(|p| !p.is_empty())
            .collect::<Vec<_>>()
            .join(":");
        out.push(parse_component(&normalized, component_type)?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_list_formats() {
        let text = "# installed\nname,version\nakismet:5.3\nwoocommerce 9.1.0\nelementor,3.20.1\n\nhello-dolly\n";
        let list = parse_component_list(text, ComponentType::Plugin).unwrap();
        let got: Vec<_> = list
            .iter()
            .map(|c| (c.slug.as_str(), c.version.as_deref()))
            .collect();
        assert_eq!(
            got,
            vec![
                ("akismet", Some("5.3")),
                ("woocommerce", Some("9.1.0")),
                ("elementor", Some("3.20.1")),
                ("hello-dolly", None),
            ]
        );
    }

    #[test]
    fn parse_valid_url() {
        let scanner = Scanner::new("https://example.com");
        assert!(scanner.is_ok());
    }

    #[test]
    fn parse_invalid_url() {
        let scanner = Scanner::new("not a url");
        assert!(scanner.is_err());
    }

    #[test]
    fn parse_component_with_version() {
        let info = parse_component("elementor:3.18.0", ComponentType::Plugin).unwrap();
        assert_eq!(info.slug, "elementor");
        assert_eq!(info.version, Some("3.18.0".to_string()));
    }

    #[test]
    fn parse_component_without_version() {
        let info = parse_component("elementor", ComponentType::Plugin).unwrap();
        assert_eq!(info.slug, "elementor");
        assert_eq!(info.version, None);
    }
}
