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
}

pub trait SecretStore {
    // `get` is used by `shtum run` placeholder resolution starting in Phase 2.
    #[allow(dead_code)]
    fn get(&self, name: &str) -> Result<Vec<u8>, StoreError>;
    fn set(&self, name: &str, value: &[u8]) -> Result<(), StoreError>;
    fn delete(&self, name: &str) -> Result<(), StoreError>;
    fn list(&self) -> Result<Vec<String>, StoreError>;
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
