use crate::store::StoreError;
use rusqlite::OptionalExtension;

#[derive(Debug, Clone)]
pub struct Channel {
    pub channel_id: String,
    pub version: i64,
    pub origin: String,
    pub request_url: String,
    pub chain_id: i64,
    pub escrow_contract: String,
    pub token: String,
    pub payee: String,
    pub payer: String,
    pub authorized_signer: String,
    pub salt: String,
    pub deposit: String,
    pub cumulative_amount: String,
    pub challenge_echo: String,
    pub state: String,
    pub close_requested_at: i64,
    pub grace_ready_at: i64,
    pub created_at: i64,
    pub last_used_at: i64,
}

pub struct ChannelDb {
    conn: std::sync::Mutex<rusqlite::Connection>,
}

impl ChannelDb {
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self, StoreError> {
        let conn = rusqlite::Connection::open(path)
            .map_err(|e| StoreError::Internal(format!("Failed to open SQLite database: {e}")))?;
        let store = Self {
            conn: std::sync::Mutex::new(conn),
        };
        store.init_table()?;
        Ok(store)
    }

    pub fn open_in_memory() -> Result<Self, StoreError> {
        let conn = rusqlite::Connection::open_in_memory()
            .map_err(|e| StoreError::Internal(format!("Failed to open in-memory SQLite: {e}")))?;
        let store = Self {
            conn: std::sync::Mutex::new(conn),
        };
        store.init_table()?;
        Ok(store)
    }

    fn init_table(&self) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS channels (
                channel_id         TEXT PRIMARY KEY,
                version            INTEGER NOT NULL DEFAULT 1,
                origin             TEXT NOT NULL,
                request_url        TEXT NOT NULL DEFAULT '',
                chain_id           INTEGER NOT NULL,
                escrow_contract    TEXT NOT NULL,
                token              TEXT NOT NULL,
                payee              TEXT NOT NULL,
                payer              TEXT NOT NULL,
                authorized_signer  TEXT NOT NULL,
                salt               TEXT NOT NULL,
                deposit            TEXT NOT NULL,
                cumulative_amount  TEXT NOT NULL,
                challenge_echo     TEXT NOT NULL,
                state              TEXT NOT NULL DEFAULT 'active',
                close_requested_at INTEGER NOT NULL DEFAULT 0,
                grace_ready_at     INTEGER NOT NULL DEFAULT 0,
                created_at         INTEGER NOT NULL,
                last_used_at       INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_channels_origin ON channels(origin);",
        )
        .map_err(|e| StoreError::Internal(format!("Failed to create channels table: {e}")))?;
        Ok(())
    }

    fn row_to_channel(row: &rusqlite::Row) -> rusqlite::Result<Channel> {
        Ok(Channel {
            channel_id: row.get("channel_id")?,
            version: row.get("version")?,
            origin: row.get("origin")?,
            request_url: row.get("request_url")?,
            chain_id: row.get("chain_id")?,
            escrow_contract: row.get("escrow_contract")?,
            token: row.get("token")?,
            payee: row.get("payee")?,
            payer: row.get("payer")?,
            authorized_signer: row.get("authorized_signer")?,
            salt: row.get("salt")?,
            deposit: row.get("deposit")?,
            cumulative_amount: row.get("cumulative_amount")?,
            challenge_echo: row.get("challenge_echo")?,
            state: row.get("state")?,
            close_requested_at: row.get("close_requested_at")?,
            grace_ready_at: row.get("grace_ready_at")?,
            created_at: row.get("created_at")?,
            last_used_at: row.get("last_used_at")?,
        })
    }

    pub fn load(&self) -> Result<Vec<Channel>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT * FROM channels")
            .map_err(|e| StoreError::Internal(format!("SQLite prepare error: {e}")))?;
        let rows = stmt
            .query_map([], Self::row_to_channel)
            .map_err(|e| StoreError::Internal(format!("SQLite query error: {e}")))?;
        let mut channels = Vec::new();
        for row in rows {
            channels.push(row.map_err(|e| StoreError::Internal(format!("SQLite row error: {e}")))?);
        }
        Ok(channels)
    }

    pub fn find(&self, channel_id: &str) -> Result<Option<Channel>, StoreError> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT * FROM channels WHERE channel_id = ?1",
            rusqlite::params![channel_id],
            Self::row_to_channel,
        )
        .optional()
        .map_err(|e| StoreError::Internal(format!("SQLite find error: {e}")))
    }

    pub fn find_by_origin(&self, origin: &str) -> Result<Vec<Channel>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT * FROM channels WHERE origin = ?1")
            .map_err(|e| StoreError::Internal(format!("SQLite prepare error: {e}")))?;
        let rows = stmt
            .query_map(rusqlite::params![origin], Self::row_to_channel)
            .map_err(|e| StoreError::Internal(format!("SQLite query error: {e}")))?;
        let mut channels = Vec::new();
        for row in rows {
            channels.push(row.map_err(|e| StoreError::Internal(format!("SQLite row error: {e}")))?);
        }
        Ok(channels)
    }

    pub fn upsert(&self, ch: &Channel) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO channels (
                channel_id, version, origin, request_url, chain_id,
                escrow_contract, token, payee, payer, authorized_signer,
                salt, deposit, cumulative_amount, challenge_echo,
                state, close_requested_at, grace_ready_at,
                created_at, last_used_at
            ) VALUES (
                ?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19
            )
            ON CONFLICT(channel_id) DO UPDATE SET
                version=excluded.version,
                origin=excluded.origin,
                request_url=excluded.request_url,
                cumulative_amount=excluded.cumulative_amount,
                deposit=excluded.deposit,
                challenge_echo=excluded.challenge_echo,
                state=excluded.state,
                close_requested_at=excluded.close_requested_at,
                grace_ready_at=excluded.grace_ready_at,
                last_used_at=excluded.last_used_at",
            rusqlite::params![
                ch.channel_id,
                ch.version,
                ch.origin,
                ch.request_url,
                ch.chain_id,
                ch.escrow_contract,
                ch.token,
                ch.payee,
                ch.payer,
                ch.authorized_signer,
                ch.salt,
                ch.deposit,
                ch.cumulative_amount,
                ch.challenge_echo,
                ch.state,
                ch.close_requested_at,
                ch.grace_ready_at,
                ch.created_at,
                ch.last_used_at,
            ],
        )
        .map_err(|e| StoreError::Internal(format!("SQLite upsert error: {e}")))?;
        Ok(())
    }

    pub fn delete(&self, channel_id: &str) -> Result<bool, StoreError> {
        let conn = self.conn.lock().unwrap();
        let count = conn
            .execute(
                "DELETE FROM channels WHERE channel_id = ?1",
                rusqlite::params![channel_id],
            )
            .map_err(|e| StoreError::Internal(format!("SQLite delete error: {e}")))?;
        Ok(count > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_channel(channel_id: &str, origin: &str) -> Channel {
        Channel {
            channel_id: channel_id.to_string(),
            version: 1,
            origin: origin.to_string(),
            request_url: "https://api.example.com/paid".to_string(),
            chain_id: 42431,
            escrow_contract: "0xe1c4d3dce17bc111181ddf716f75bae49e61a336".to_string(),
            token: "0x20c0000000000000000000000000000000000000".to_string(),
            payee: "0x3333333333333333333333333333333333333333".to_string(),
            payer: "0x1111111111111111111111111111111111111111".to_string(),
            authorized_signer: "0x1111111111111111111111111111111111111111".to_string(),
            salt: format!("0x{}", "ab".repeat(32)),
            deposit: "100000".to_string(),
            cumulative_amount: "0".to_string(),
            challenge_echo: "echo-data".to_string(),
            state: "active".to_string(),
            close_requested_at: 0,
            grace_ready_at: 0,
            created_at: 1700000000,
            last_used_at: 1700000000,
        }
    }

    #[test]
    fn crud_lifecycle() {
        let db = ChannelDb::open_in_memory().unwrap();

        // find on empty db
        assert!(db.find("0xmissing").unwrap().is_none());

        // upsert + find
        db.upsert(&test_channel("0xch1", "origin-a")).unwrap();
        let fetched = db.find("0xch1").unwrap().unwrap();
        assert_eq!(fetched.channel_id, "0xch1");
        assert_eq!(fetched.deposit, "100000");
        assert_eq!(fetched.origin, "origin-a");

        // load + find_by_origin with multiple channels
        db.upsert(&test_channel("0xch2", "origin-b")).unwrap();
        db.upsert(&test_channel("0xch3", "origin-a")).unwrap();
        assert_eq!(db.load().unwrap().len(), 3);
        assert_eq!(db.find_by_origin("origin-a").unwrap().len(), 2);
        assert_eq!(db.find_by_origin("origin-b").unwrap().len(), 1);
        assert!(db.find_by_origin("origin-missing").unwrap().is_empty());

        // delete
        assert!(db.delete("0xch1").unwrap());
        assert!(db.find("0xch1").unwrap().is_none());
        assert!(!db.delete("0xch1").unwrap());
        assert_eq!(db.load().unwrap().len(), 2);
    }

    #[test]
    fn upsert_preserves_created_at() {
        let db = ChannelDb::open_in_memory().unwrap();
        let ch = test_channel("0xch1", "https://rpc.test");
        db.upsert(&ch).unwrap();

        let mut updated = ch.clone();
        updated.cumulative_amount = "5000".to_string();
        updated.last_used_at = 1700001000;
        updated.created_at = 9999999999;
        db.upsert(&updated).unwrap();

        let fetched = db.find("0xch1").unwrap().unwrap();
        assert_eq!(fetched.cumulative_amount, "5000");
        assert_eq!(fetched.last_used_at, 1700001000);
        assert_eq!(fetched.created_at, 1700000000);
    }

    #[test]
    fn roundtrip_all_fields() {
        let db = ChannelDb::open_in_memory().unwrap();

        let ch = Channel {
            channel_id: "0xdeadbeef".to_string(),
            version: 2,
            origin: "https://api.prod.example.com".to_string(),
            request_url: "https://api.prod.example.com/v1/pay".to_string(),
            chain_id: 4217,
            escrow_contract: "0x33b901018174ddabe4841042ab76ba85d4e24f25".to_string(),
            token: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            payee: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
            payer: "0xcccccccccccccccccccccccccccccccccccccccc".to_string(),
            authorized_signer: "0xdddddddddddddddddddddddddddddddddddddddd".to_string(),
            salt: format!("0x{}", "ff".repeat(32)),
            deposit: "340282366920938463463374607431768211455".to_string(),
            cumulative_amount: "999999".to_string(),
            challenge_echo: "base64-encoded-echo".to_string(),
            state: "closing".to_string(),
            close_requested_at: 1700000500,
            grace_ready_at: 1700086900,
            created_at: 1700000000,
            last_used_at: 1700000999,
        };

        db.upsert(&ch).unwrap();
        let f = db.find("0xdeadbeef").unwrap().unwrap();

        assert_eq!(f.channel_id, ch.channel_id);
        assert_eq!(f.version, 2);
        assert_eq!(f.origin, ch.origin);
        assert_eq!(f.request_url, ch.request_url);
        assert_eq!(f.chain_id, 4217);
        assert_eq!(f.escrow_contract, ch.escrow_contract);
        assert_eq!(f.token, ch.token);
        assert_eq!(f.payee, ch.payee);
        assert_eq!(f.payer, ch.payer);
        assert_eq!(f.authorized_signer, ch.authorized_signer);
        assert_eq!(f.salt, ch.salt);
        assert_eq!(f.deposit, ch.deposit);
        assert_eq!(f.cumulative_amount, "999999");
        assert_eq!(f.challenge_echo, ch.challenge_echo);
        assert_eq!(f.state, "closing");
        assert_eq!(f.close_requested_at, 1700000500);
        assert_eq!(f.grace_ready_at, 1700086900);
        assert_eq!(f.created_at, 1700000000);
        assert_eq!(f.last_used_at, 1700000999);
    }

    #[test]
    fn compatible_with_wallet_schema() {
        let db = ChannelDb::open_in_memory().unwrap();

        {
            let conn = db.conn.lock().unwrap();
            conn.execute(
                "INSERT INTO channels (
                    channel_id, version, origin, request_url, chain_id,
                    escrow_contract, token, payee, payer, authorized_signer,
                    salt, deposit, cumulative_amount, challenge_echo,
                    state, close_requested_at, grace_ready_at,
                    created_at, last_used_at
                ) VALUES (
                    '0xwallet_ch', 1, 'https://rpc.tempo.xyz', '',
                    4217, '0x33b901', '0xtoken', '0xpayee', '0xpayer',
                    '0xsigner', '0xsalt', '50000', '1000', 'echo',
                    'active', 0, 0, 1700000000, 1700000000
                )",
                [],
            )
            .unwrap();
        }

        let ch = db.find("0xwallet_ch").unwrap().unwrap();
        assert_eq!(ch.channel_id, "0xwallet_ch");
        assert_eq!(ch.state, "active");
        assert_eq!(ch.deposit, "50000");
        assert_eq!(ch.cumulative_amount, "1000");
    }
}
