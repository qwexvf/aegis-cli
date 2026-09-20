//! npm registry configuration: which registry a package actually comes from.
//!
//! The gate looked every npm package up on `registry.npmjs.org`. On a private
//! registry — Verdaccio, Artifactory, GitHub Packages, a scoped `@company/*`
//! feed — every internal package 404s there, and a fail-closed gate turns a
//! 404 into a blocked install. The result was that nobody using a private
//! registry could install anything at all.
//!
//! Resolution order matches npm's own, narrowest first:
//!   1. `@scope:registry=` for the package's scope
//!   2. `registry=`
//!   3. the public default
//!
//! Sources, later overriding earlier: `~/.npmrc`, then `./.npmrc`, then
//! `NPM_CONFIG_REGISTRY`.
//!
//! Auth tokens (`//host/path/:_authToken=`) are read so a private lookup can
//! succeed, and are never logged.

use std::collections::HashMap;
use std::path::Path;

pub(crate) const PUBLIC_NPM: &str = "https://registry.npmjs.org";

#[derive(Debug, Default, Clone)]
pub(crate) struct NpmConfig {
    /// `registry=`
    default_registry: Option<String>,
    /// `@scope:registry=` keyed by scope, including the leading `@`.
    scoped: HashMap<String, String>,
    /// `_authToken` keyed by the `//host/path/` prefix it was declared under.
    tokens: HashMap<String, String>,
}

impl NpmConfig {
    /// Load from `~/.npmrc`, then `./.npmrc`, then the environment.
    pub(crate) fn load(project_dir: &Path) -> NpmConfig {
        let mut cfg = NpmConfig::default();
        if let Some(home) = std::env::var_os("HOME") {
            cfg.merge_file(&Path::new(&home).join(".npmrc"));
        }
        cfg.merge_file(&project_dir.join(".npmrc"));
        if let Ok(r) = std::env::var("NPM_CONFIG_REGISTRY") {
            if !r.trim().is_empty() {
                cfg.default_registry = Some(normalize(&r));
            }
        }
        cfg
    }

    fn merge_file(&mut self, path: &Path) {
        let Ok(text) = std::fs::read_to_string(path) else {
            return;
        };
        for line in text.lines() {
            let l = line.trim();
            if l.is_empty() || l.starts_with('#') || l.starts_with(';') {
                continue;
            }
            let Some((k, v)) = l.split_once('=') else {
                continue;
            };
            let (k, v) = (k.trim(), expand_env(v.trim()));
            if v.is_empty() {
                continue;
            }
            if k == "registry" {
                self.default_registry = Some(normalize(&v));
            } else if let Some(scope) = k.strip_suffix(":registry") {
                if scope.starts_with('@') {
                    self.scoped.insert(scope.to_string(), normalize(&v));
                }
            } else if let Some(prefix) = k.strip_suffix(":_authToken") {
                self.tokens
                    .insert(prefix.trim_end_matches('/').to_string(), v);
            }
        }
    }

    /// The registry `name` resolves to.
    pub(crate) fn registry_for(&self, name: &str) -> String {
        if let Some(scope) = scope_of(name) {
            if let Some(r) = self.scoped.get(scope) {
                return r.clone();
            }
        }
        self.default_registry
            .clone()
            .unwrap_or_else(|| PUBLIC_NPM.to_string())
    }

    /// The auth token configured for `registry`, if any.
    pub(crate) fn token_for(&self, registry: &str) -> Option<String> {
        // `.npmrc` keys tokens by `//host/path/`, so compare on that shape.
        let key = registry
            .trim_end_matches('/')
            .strip_prefix("https:")
            .or_else(|| registry.trim_end_matches('/').strip_prefix("http:"))
            .unwrap_or(registry);
        self.tokens.get(key).cloned()
    }

    /// Is this the public npm registry?
    ///
    /// The distinction matters for policy: a 404 on the public registry is a
    /// real signal (the package does not exist, and the name is squattable),
    /// while a 404 or 401 on a private host usually means we lack access
    /// rather than that the package is absent.
    pub(crate) fn is_public(registry: &str) -> bool {
        let r = registry.trim_end_matches('/');
        r == PUBLIC_NPM || r == "http://registry.npmjs.org" || r.ends_with("registry.npmjs.org")
    }
}

/// `@scope/name` → `@scope`.
fn scope_of(name: &str) -> Option<&str> {
    name.strip_prefix('@')
        .and_then(|r| r.split_once('/'))
        .map(|(s, _)| &name[..s.len() + 1])
}

fn normalize(url: &str) -> String {
    url.trim().trim_end_matches('/').to_string()
}

/// `.npmrc` allows `${VAR}` interpolation; an unset variable yields empty,
/// which the caller skips rather than sending a literal `${VAR}` as a token.
fn expand_env(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    let mut rest = v;
    while let Some(i) = rest.find("${") {
        out.push_str(&rest[..i]);
        let Some(j) = rest[i..].find('}') else {
            out.push_str(&rest[i..]);
            return out;
        };
        let var = &rest[i + 2..i + j];
        out.push_str(&std::env::var(var).unwrap_or_default());
        rest = &rest[i + j + 1..];
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_from(body: &str) -> NpmConfig {
        // Unique per call: tests run in parallel, and a shared directory means
        // they overwrite and delete each other's .npmrc.
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let d = std::env::temp_dir().join(format!(
            "aegis-npmrc-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join(".npmrc"), body).unwrap();
        let mut c = NpmConfig::default();
        c.merge_file(&d.join(".npmrc"));
        std::fs::remove_dir_all(&d).ok();
        c
    }

    #[test]
    fn a_default_registry_replaces_the_public_one() {
        let c = cfg_from("registry=http://localhost:4873\n");
        assert_eq!(c.registry_for("lodash"), "http://localhost:4873");
        assert!(!NpmConfig::is_public("http://localhost:4873"));
    }

    #[test]
    fn a_scoped_registry_wins_for_its_scope_only() {
        let c = cfg_from(
            "registry=https://registry.npmjs.org\n@acme:registry=https://npm.acme.internal\n",
        );
        assert_eq!(c.registry_for("@acme/widget"), "https://npm.acme.internal");
        assert_eq!(c.registry_for("@other/thing"), "https://registry.npmjs.org");
        assert_eq!(c.registry_for("lodash"), "https://registry.npmjs.org");
    }

    #[test]
    fn with_no_config_the_public_registry_is_used() {
        let c = NpmConfig::default();
        assert_eq!(c.registry_for("lodash"), PUBLIC_NPM);
        assert!(NpmConfig::is_public(&c.registry_for("lodash")));
    }

    #[test]
    fn auth_tokens_are_matched_to_their_registry() {
        let c = cfg_from(
            "registry=https://npm.acme.internal\n//npm.acme.internal/:_authToken=secret123\n",
        );
        assert_eq!(
            c.token_for("https://npm.acme.internal"),
            Some("secret123".to_string())
        );
        assert_eq!(c.token_for("https://registry.npmjs.org"), None);
    }

    #[test]
    fn env_interpolation_is_expanded_and_an_unset_var_is_dropped() {
        // `${NPM_TOKEN}` is the conventional shape in a committed .npmrc.
        let c = cfg_from("//npm.acme.internal/:_authToken=${AEGIS_TEST_UNSET_TOKEN}\n");
        assert_eq!(c.token_for("https://npm.acme.internal"), None);
        assert_eq!(expand_env("plain"), "plain");
    }

    #[test]
    fn trailing_slashes_and_comments_do_not_confuse_it() {
        let c = cfg_from("# a comment\n; another\nregistry=http://localhost:4873/\n");
        assert_eq!(c.registry_for("x"), "http://localhost:4873");
    }

    #[test]
    fn scope_extraction() {
        assert_eq!(scope_of("@acme/widget"), Some("@acme"));
        assert_eq!(scope_of("lodash"), None);
        assert_eq!(scope_of("@broken"), None);
    }
}
