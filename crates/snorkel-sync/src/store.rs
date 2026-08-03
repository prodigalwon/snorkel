//! redb-backed persistent state (engine decided 2026-08-02: crash-safe,
//! MVCC, readers never block the writer — fits the pinned dns workers).
//!
//! Client rule 6 (atomic advance) lives here: diff application and
//! checkpoint advance MUST commit in one transaction, so a crash
//! resumes at the prior anchor, never in between. v0 persists only the
//! checkpoint; the replica tables join the same transaction discipline
//! when diff descent lands.

use std::path::Path;

use redb::{Database, TableDefinition};

use crate::checkpoint::Checkpoint;

const CHECKPOINT_TABLE: TableDefinition<'_, &str, &[u8]> = TableDefinition::new("checkpoint");
const CHECKPOINT_KEY: &str = "current";

pub struct Store {
    db: Database,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self, String> {
        let db = Database::create(path).map_err(|e| format!("redb open: {e}"))?;
        Ok(Store { db })
    }

    /// Persist the checkpoint. One transaction; callers add replica
    /// mutations to the same transaction when diff descent lands.
    pub fn put_checkpoint(&self, c: &Checkpoint) -> Result<(), String> {
        let tx = self.db.begin_write().map_err(|e| format!("redb write: {e}"))?;
        {
            let mut table = tx
                .open_table(CHECKPOINT_TABLE)
                .map_err(|e| format!("redb table: {e}"))?;
            table
                .insert(CHECKPOINT_KEY, c.store_bytes().as_slice())
                .map_err(|e| format!("redb insert: {e}"))?;
        }
        tx.commit().map_err(|e| format!("redb commit: {e}"))
    }

    /// Load + integrity-check the persisted checkpoint. `Ok(None)` on a
    /// fresh store (caller falls back to the release-baked checkpoint).
    pub fn checkpoint(&self) -> Result<Option<Checkpoint>, String> {
        let tx = self.db.begin_read().map_err(|e| format!("redb read: {e}"))?;
        let table = match tx.open_table(CHECKPOINT_TABLE) {
            Ok(t) => t,
            // Table absent = fresh store.
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(format!("redb table: {e}")),
        };
        match table.get(CHECKPOINT_KEY).map_err(|e| format!("redb get: {e}"))? {
            None => Ok(None),
            Some(bytes) => Checkpoint::load(bytes.value()).map(Some),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::checkpoint::Authority;

    #[test]
    fn persist_and_reload() {
        let dir = std::env::temp_dir().join(format!("snorkel-sync-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("store.redb");
        let _ = std::fs::remove_file(&path);

        let c = Checkpoint::sealed(
            [3; 32],
            55,
            [4; 32],
            [5; 32],
            2,
            vec![Authority { public: vec![1, 2, 3], weight: 9 }],
        );
        {
            let store = Store::open(&path).unwrap();
            assert!(store.checkpoint().unwrap().is_none());
            store.put_checkpoint(&c).unwrap();
        }
        // Reopen: crash-restart shape.
        let store = Store::open(&path).unwrap();
        assert_eq!(store.checkpoint().unwrap(), Some(c));
        let _ = std::fs::remove_file(&path);
    }
}
