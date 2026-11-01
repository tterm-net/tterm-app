//! The vault's keeper for the GUI checks on Linux (from 0.7.0), in debug
//! builds only: with `TTERM_TEST_KEEPER=1` the app's vault keeps its KEK in
//! memory and its LocalAuthentication gate passes, so a check can make, open
//! and lock the vault, allow a new browser and move servers in the real app
//! under Xvfb. With `TTERM_TEST_KEEPER_DENY=1` too, every gate fails, as a
//! cancelled Touch ID does. A release build has none of this: the module is
//! compiled only with debug assertions (main.rs).

use std::collections::HashMap;
use std::sync::Mutex;
use tterm_engine::vault::Keeper;

/// Whether the checks asked for the test keeper.
pub fn wanted() -> bool {
    std::env::var("TTERM_TEST_KEEPER").as_deref() == Ok("1")
}

#[derive(Default)]
pub struct TestKeeper {
    keks: Mutex<HashMap<String, Vec<u8>>>,
}

impl TestKeeper {
    pub fn new() -> TestKeeper {
        eprintln!("tterm: the vault's keeper is the test one (TTERM_TEST_KEEPER=1): no keychain, no Touch ID");
        TestKeeper::default()
    }
}

impl Keeper for TestKeeper {
    fn available(&self) -> bool {
        true
    }

    /// The gate: passes, or with TTERM_TEST_KEEPER_DENY=1 fails as a
    /// cancelled Touch ID does. Each is written to stderr for the check.
    fn authenticate(&self, reason: &str) -> Result<(), String> {
        if std::env::var("TTERM_TEST_KEEPER_DENY").as_deref() == Ok("1") {
            eprintln!("tterm: test keeper: \"{reason}\": denied");
            return Err("Canceled by user.".into());
        }
        eprintln!("tterm: test keeper: \"{reason}\": passed");
        Ok(())
    }

    fn save_kek(&self, vault_id: &str, kek: &[u8]) -> Result<(), String> {
        self.keks.lock().unwrap().insert(vault_id.to_string(), kek.to_vec());
        Ok(())
    }

    fn load_kek(&self, vault_id: &str) -> Result<Option<Vec<u8>>, String> {
        Ok(self.keks.lock().unwrap().get(vault_id).cloned())
    }

    fn delete_kek(&self, vault_id: &str) -> Result<(), String> {
        self.keks.lock().unwrap().remove(vault_id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_keeps_the_kek_in_memory_and_its_gate_passes() {
        let k = TestKeeper::default();
        assert!(k.available());
        assert_eq!(k.load_kek("v1").unwrap(), None);
        k.save_kek("v1", &[7; 32]).unwrap();
        assert_eq!(k.load_kek("v1").unwrap(), Some(vec![7; 32]));
        k.delete_kek("v1").unwrap();
        assert_eq!(k.load_kek("v1").unwrap(), None);
        // The deny switch is read at each check; it is not set here.
        if std::env::var_os("TTERM_TEST_KEEPER_DENY").is_none() {
            assert!(k.authenticate("open your tTerm vault").is_ok());
        }
    }
}
