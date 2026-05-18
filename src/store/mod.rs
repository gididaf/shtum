// Copyright 2026 Gidi Dafner
// SPDX-License-Identifier: MIT

use thiserror::Error;

pub mod keychain;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("secret `{0}` not found")]
    NotFound(String),
    #[error("invalid secret name `{0}`: {1}")]
    InvalidName(String, &'static str),
    #[error("backend error: {0}")]
    Backend(String),
    #[error("target `{0}` already exists; pass --force to overwrite")]
    AlreadyExists(String),
}

pub trait SecretStore {
    // `get` is used by `shtum run` placeholder resolution starting in Phase 2.
    #[allow(dead_code)]
    fn get(&self, name: &str) -> Result<Vec<u8>, StoreError>;
    fn set(&self, name: &str, value: &[u8]) -> Result<(), StoreError>;
    fn delete(&self, name: &str) -> Result<(), StoreError>;
    fn list(&self) -> Result<Vec<String>, StoreError>;

    /// Add a new secret. Refuses with `AlreadyExists` if `name` is
    /// already stored and `force` is false. `set` is the unconditional
    /// upsert primitive; `add` is `set` with a precondition. Callers
    /// that want to distinguish "create new" from "replace existing"
    /// should go through `add` rather than `set`.
    fn add(&self, name: &str, value: &[u8], force: bool) -> Result<(), StoreError> {
        if !force {
            let names = self.list()?;
            if names.iter().any(|n| n == name) {
                return Err(StoreError::AlreadyExists(name.to_string()));
            }
        }
        self.set(name, value)
    }

    /// Rename `old` to `new`. No-op if `old == new`. Refuses with
    /// `AlreadyExists` if `new` is already a stored name and `force` is
    /// false. The default impl is `list` (existence check) → `get(old)` →
    /// `set(new)` → `delete(old)`; if a step after `set` fails, both
    /// entries may briefly coexist with the same value — a re-run finishes
    /// the move. Backends with a native rename should override.
    fn rename(&self, old: &str, new: &str, force: bool) -> Result<(), StoreError> {
        if old == new {
            return Ok(());
        }
        if !force {
            let names = self.list()?;
            if names.iter().any(|n| n == new) {
                return Err(StoreError::AlreadyExists(new.to_string()));
            }
        }
        let value = self.get(old)?;
        self.set(new, &value)?;
        self.delete(old)?;
        Ok(())
    }
}

pub fn validate_name(name: &str) -> Result<(), StoreError> {
    if name.is_empty() {
        return Err(StoreError::InvalidName(
            name.to_string(),
            "must not be empty",
        ));
    }
    let ok = name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.');
    if !ok {
        return Err(StoreError::InvalidName(
            name.to_string(),
            "only [A-Za-z0-9_.-] are allowed",
        ));
    }
    Ok(())
}

pub fn default_store() -> keychain::KeychainStore {
    keychain::KeychainStore::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    struct MockStore {
        items: RefCell<BTreeMap<String, Vec<u8>>>,
    }

    impl MockStore {
        fn new() -> Self {
            Self { items: RefCell::new(BTreeMap::new()) }
        }
        fn seed(items: &[(&str, &[u8])]) -> Self {
            let s = Self::new();
            for (k, v) in items {
                s.set(k, v).unwrap();
            }
            s
        }
    }

    impl SecretStore for MockStore {
        fn get(&self, name: &str) -> Result<Vec<u8>, StoreError> {
            self.items
                .borrow()
                .get(name)
                .cloned()
                .ok_or_else(|| StoreError::NotFound(name.to_string()))
        }
        fn set(&self, name: &str, value: &[u8]) -> Result<(), StoreError> {
            self.items.borrow_mut().insert(name.to_string(), value.to_vec());
            Ok(())
        }
        fn delete(&self, name: &str) -> Result<(), StoreError> {
            self.items
                .borrow_mut()
                .remove(name)
                .map(|_| ())
                .ok_or_else(|| StoreError::NotFound(name.to_string()))
        }
        fn list(&self) -> Result<Vec<String>, StoreError> {
            Ok(self.items.borrow().keys().cloned().collect())
        }
    }

    #[test]
    fn add_stores_when_name_is_free() {
        let s = MockStore::new();
        s.add("FOO", b"hunter2", false).expect("add new should succeed");
        assert_eq!(s.get("FOO").unwrap(), b"hunter2");
    }

    #[test]
    fn add_refuses_when_name_already_exists() {
        let s = MockStore::seed(&[("FOO", b"old")]);
        let err = s.add("FOO", b"new", false).expect_err("should refuse");
        assert!(matches!(err, StoreError::AlreadyExists(ref n) if n == "FOO"));
        // Existing value untouched.
        assert_eq!(s.get("FOO").unwrap(), b"old");
    }

    #[test]
    fn add_with_force_overwrites_existing_value() {
        let s = MockStore::seed(&[("FOO", b"old")]);
        s.add("FOO", b"new", true).expect("force should succeed");
        assert_eq!(s.get("FOO").unwrap(), b"new");
    }

    #[test]
    fn rename_moves_value_and_drops_old_name() {
        let s = MockStore::seed(&[("OLD", b"hunter2")]);
        s.rename("OLD", "NEW", false).expect("rename should succeed");
        assert_eq!(s.get("NEW").unwrap(), b"hunter2");
        assert!(matches!(s.get("OLD"), Err(StoreError::NotFound(_))));
    }

    #[test]
    fn rename_refuses_when_target_exists() {
        let s = MockStore::seed(&[("OLD", b"a"), ("NEW", b"b")]);
        let err = s.rename("OLD", "NEW", false).expect_err("should refuse");
        assert!(matches!(err, StoreError::AlreadyExists(ref n) if n == "NEW"));
        // Both originals untouched.
        assert_eq!(s.get("OLD").unwrap(), b"a");
        assert_eq!(s.get("NEW").unwrap(), b"b");
    }

    #[test]
    fn rename_with_force_overwrites_target() {
        let s = MockStore::seed(&[("OLD", b"a"), ("NEW", b"b")]);
        s.rename("OLD", "NEW", true).expect("force should succeed");
        assert_eq!(s.get("NEW").unwrap(), b"a");
        assert!(matches!(s.get("OLD"), Err(StoreError::NotFound(_))));
    }

    #[test]
    fn rename_missing_source_returns_not_found() {
        let s = MockStore::new();
        let err = s.rename("MISSING", "NEW", false).expect_err("should fail");
        assert!(matches!(err, StoreError::NotFound(ref n) if n == "MISSING"));
    }

    #[test]
    fn rename_same_name_is_noop() {
        let s = MockStore::seed(&[("X", b"v")]);
        s.rename("X", "X", false).expect("same-name rename is no-op");
        s.rename("X", "X", true).expect("force same-name is also no-op");
        assert_eq!(s.get("X").unwrap(), b"v");
    }

    #[test]
    fn rename_same_name_no_op_does_not_require_existence() {
        // A no-op rename of a missing name shouldn't error; nothing changes.
        let s = MockStore::new();
        s.rename("MISSING", "MISSING", false).expect("noop");
    }
}
