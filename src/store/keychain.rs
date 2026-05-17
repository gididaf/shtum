// Copyright 2026 Gidi Dafner
// SPDX-License-Identifier: Apache-2.0

use crate::store::{SecretStore, StoreError};
use security_framework::item::{ItemClass, ItemSearchOptions, SearchResult};
use security_framework::passwords::{
    delete_generic_password, get_generic_password, set_generic_password,
};

pub const SERVICE: &str = "shtum";

const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;

pub struct KeychainStore;

impl KeychainStore {
    pub fn new() -> Self {
        Self
    }
}

impl Default for KeychainStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretStore for KeychainStore {
    fn get(&self, name: &str) -> Result<Vec<u8>, StoreError> {
        get_generic_password(SERVICE, name).map_err(|e| map_err(name, e))
    }

    fn set(&self, name: &str, value: &[u8]) -> Result<(), StoreError> {
        set_generic_password(SERVICE, name, value).map_err(|e| map_err(name, e))
    }

    fn delete(&self, name: &str) -> Result<(), StoreError> {
        delete_generic_password(SERVICE, name).map_err(|e| map_err(name, e))
    }

    fn list(&self) -> Result<Vec<String>, StoreError> {
        let results = ItemSearchOptions::new()
            .class(ItemClass::generic_password())
            .load_attributes(true)
            .limit(i32::MAX as i64)
            .search();

        let results = match results {
            Ok(r) => r,
            Err(e) if e.code() == ERR_SEC_ITEM_NOT_FOUND => return Ok(Vec::new()),
            Err(e) => return Err(StoreError::Backend(e.to_string())),
        };

        let mut names = Vec::new();
        for r in results {
            let attrs = match r.simplify_dict() {
                Some(a) => a,
                None => continue,
            };
            if attrs.get("svce").map(String::as_str) == Some(SERVICE) {
                if let Some(acct) = attrs.get("acct") {
                    names.push(acct.clone());
                }
            }
        }
        names.sort();
        names.dedup();
        Ok(names)
    }
}

fn map_err(name: &str, e: security_framework::base::Error) -> StoreError {
    if e.code() == ERR_SEC_ITEM_NOT_FOUND {
        StoreError::NotFound(name.to_string())
    } else {
        StoreError::Backend(e.to_string())
    }
}

#[allow(dead_code)]
fn _assert_search_result_type(r: &SearchResult) -> &SearchResult {
    r
}
