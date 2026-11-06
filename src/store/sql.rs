//! SQL-backed [`Store`]: Postgres, SQLite or any driver implementing [`SqlDriver`].
//!
//! Ported from mppx's `Store.sql()`: values live as JSON text in one table
//! (`mppx_store` by default, created on first use), and every write is a single
//! statement, so the atomic methods need no interactive transactions.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};

use super::{Store, StoreError};

/// Placeholder style of a [`SqlDriver`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SqlDialect {
    /// Numbered placeholders (`$1`, `$2`, ...).
    Postgres,
    /// Positional `?` placeholders (SQLite, libSQL, D1).
    Sqlite,
}

/// A positional statement parameter.
#[derive(Debug, Clone, PartialEq)]
pub enum SqlParam {
    /// A `TEXT` value.
    Text(String),
    /// A `DOUBLE PRECISION` value, or `NULL`.
    Float(Option<f64>),
}

/// Runs one SQL statement for [`SqlStore`].
///
/// Implemented for `tokio_postgres::Client` (feature `postgres-store`) and
/// `Arc<std::sync::Mutex<rusqlite::Connection>>` (feature `sqlite-store`); implement it
/// to plug in another driver or a connection pool.
pub trait SqlDriver: Send + Sync {
    /// The driver's placeholder style. Statements are written with `?` and
    /// numbered for [`SqlDialect::Postgres`].
    fn dialect(&self) -> SqlDialect;

    /// Runs `sql` with `params` and returns the first column of each result row as text.
    fn query<'a>(
        &'a self,
        sql: &'a str,
        params: &'a [SqlParam],
    ) -> Pin<Box<dyn Future<Output = Result<Vec<String>, StoreError>> + Send + 'a>>;
}

/// Atomic [`Store`] on a SQL database, as mppx's `Store.sql()`.
///
/// The table has columns `key TEXT PRIMARY KEY, value TEXT NOT NULL, expires DOUBLE
/// PRECISION` (`expires` in milliseconds since the Unix epoch, set only by
/// [`Store::put_if_absent_with_ttl`]). Rows past their `expires` read as absent
/// and are replaced by the next insert. Needs `ON CONFLICT` and `RETURNING`
/// (Postgres, SQLite 3.35+).
///
/// ```ignore
/// let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls).await?;
/// tokio::spawn(connection);
/// let store = mpp::SqlStore::new(client).with_table("billing.mppx_store")?;
/// ```
pub struct SqlStore<D> {
    driver: D,
    table: String,
    create_table: bool,
    ready: AtomicBool,
}

impl<D: SqlDriver> SqlStore<D> {
    /// A store in the `mppx_store` table, created on first use.
    pub fn new(driver: D) -> Self {
        Self {
            driver,
            table: "mppx_store".to_owned(),
            create_table: true,
            ready: AtomicBool::new(false),
        }
    }

    /// Uses `table`, optionally schema-qualified (`schema.table`).
    ///
    /// Fails for names that are not plain SQL identifiers.
    pub fn with_table(mut self, table: impl Into<String>) -> Result<Self, StoreError> {
        let table = table.into();
        if !is_valid_table(&table) {
            return Err(StoreError::Internal(format!(
                "Invalid SQL store table name: \"{table}\"."
            )));
        }
        self.table = table;
        Ok(self)
    }

    /// Whether to run `CREATE TABLE IF NOT EXISTS` on first use (default `true`).
    /// Pass `false` when migrations create the table.
    pub fn with_create_table(mut self, create_table: bool) -> Self {
        self.create_table = create_table;
        self
    }

    /// Deletes rows whose `expires` has passed and returns how many it removed.
    ///
    /// Expired claims read as absent and are replaced by the next insert of the same
    /// key, but replay keys rarely repeat, so call this periodically (for example from
    /// a timer) to keep the table from growing. Live and permanent rows are never
    /// touched. mppx's `Store.sql()` has no equivalent.
    pub async fn purge_expired(&self) -> Result<u64, StoreError> {
        let rows = self
            .query(
                "DELETE FROM {table} WHERE expires IS NOT NULL AND expires <= ? RETURNING key",
                &[SqlParam::Float(Some(now_ms()))],
            )
            .await?;
        Ok(rows.len() as u64)
    }

    async fn ensure_table(&self) -> Result<(), StoreError> {
        if !self.create_table || self.ready.load(Ordering::Acquire) {
            return Ok(());
        }
        let create = format!(
            "CREATE TABLE IF NOT EXISTS {} (key TEXT PRIMARY KEY, value TEXT NOT NULL, expires DOUBLE PRECISION)",
            self.table
        );
        if let Err(error) = self.driver.query(&create, &[]).await {
            // A concurrent CREATE TABLE IF NOT EXISTS from another process can fail on
            // Postgres (duplicate catalog row) although the table now exists: probe it.
            let probe = format!("SELECT key FROM {} WHERE 1 = 0", self.table);
            if self.driver.query(&probe, &[]).await.is_err() {
                return Err(error);
            }
        }
        self.ready.store(true, Ordering::Release);
        Ok(())
    }

    async fn query(&self, text: &str, params: &[SqlParam]) -> Result<Vec<String>, StoreError> {
        self.ensure_table().await?;
        let text = text.replace("{table}", &self.table);
        let text = match self.driver.dialect() {
            SqlDialect::Sqlite => text,
            SqlDialect::Postgres => number_placeholders(&text),
        };
        self.driver.query(&text, params).await
    }

    /// The live raw value of `key`.
    async fn read(&self, key: &str) -> Result<Option<String>, StoreError> {
        let rows = self
            .query(
                "SELECT value FROM {table} WHERE key = ? AND (expires IS NULL OR expires > ?)",
                &[text(key), SqlParam::Float(Some(now_ms()))],
            )
            .await?;
        Ok(rows.into_iter().next())
    }

    /// Inserts `raw` if `key` is absent or expired, in one statement.
    async fn claim(
        &self,
        key: &str,
        raw: String,
        expires: Option<f64>,
    ) -> Result<bool, StoreError> {
        let rows = self
            .query(
                "INSERT INTO {table} AS existing (key, value, expires) VALUES (?, ?, ?) \
                 ON CONFLICT (key) DO UPDATE SET value = excluded.value, expires = excluded.expires \
                 WHERE existing.expires IS NOT NULL AND existing.expires <= ? RETURNING key",
                &[
                    text(key),
                    SqlParam::Text(raw),
                    SqlParam::Float(expires),
                    SqlParam::Float(Some(now_ms())),
                ],
            )
            .await?;
        Ok(!rows.is_empty())
    }

    /// Writes `value` (or deletes, for `None`) only if `key` still holds the live raw `expected`.
    async fn swap(
        &self,
        key: &str,
        expected: &str,
        value: Option<&str>,
    ) -> Result<bool, StoreError> {
        let now = SqlParam::Float(Some(now_ms()));
        let rows = match value {
            Some(value) => {
                self.query(
                    "UPDATE {table} SET value = ?, expires = NULL WHERE key = ? AND value = ? \
                     AND (expires IS NULL OR expires > ?) RETURNING key",
                    &[text(value), text(key), text(expected), now],
                )
                .await?
            }
            None => {
                self.query(
                    "DELETE FROM {table} WHERE key = ? AND value = ? \
                     AND (expires IS NULL OR expires > ?) RETURNING key",
                    &[text(key), text(expected), now],
                )
                .await?
            }
        };
        Ok(!rows.is_empty())
    }
}

impl<D: SqlDriver> Store for SqlStore<D> {
    fn get(
        &self,
        key: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<serde_json::Value>, StoreError>> + Send + '_>>
    {
        let key = key.to_owned();
        Box::pin(async move { self.read(&key).await?.as_deref().map(parse).transpose() })
    }

    fn put(
        &self,
        key: &str,
        value: serde_json::Value,
    ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + Send + '_>> {
        let key = key.to_owned();
        Box::pin(async move {
            self.query(
                "INSERT INTO {table} (key, value, expires) VALUES (?, ?, ?) \
                 ON CONFLICT (key) DO UPDATE SET value = excluded.value, expires = excluded.expires",
                &[text(&key), SqlParam::Text(serialize(&value)?), SqlParam::Float(None)],
            )
            .await?;
            Ok(())
        })
    }

    fn delete(
        &self,
        key: &str,
    ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + Send + '_>> {
        let key = key.to_owned();
        Box::pin(async move {
            self.query("DELETE FROM {table} WHERE key = ?", &[text(&key)])
                .await?;
            Ok(())
        })
    }

    fn compare_exchange(
        &self,
        key: &str,
        expected: Option<serde_json::Value>,
        value: Option<serde_json::Value>,
    ) -> Pin<Box<dyn Future<Output = Result<bool, StoreError>> + Send + '_>> {
        let key = key.to_owned();
        Box::pin(async move {
            let value = value.as_ref().map(serialize).transpose()?;
            let Some(expected) = expected else {
                return match value {
                    Some(value) => self.claim(&key, value, None).await,
                    None => Ok(self.read(&key).await?.is_none()),
                };
            };
            let expected_raw = serialize(&expected)?;
            if self.swap(&key, &expected_raw, value.as_deref()).await? {
                return Ok(true);
            }
            // The stored text may encode an equal value differently (another writer's
            // key order or number format): compare values, then swap against that text.
            match self.read(&key).await? {
                Some(current) if current != expected_raw && parse(&current)? == expected => {
                    self.swap(&key, &current, value.as_deref()).await
                }
                _ => Ok(false),
            }
        })
    }

    fn put_if_absent(
        &self,
        key: &str,
        value: serde_json::Value,
    ) -> Pin<Box<dyn Future<Output = Result<bool, StoreError>> + Send + '_>> {
        let key = key.to_owned();
        Box::pin(async move { self.claim(&key, serialize(&value)?, None).await })
    }

    fn put_if_absent_with_ttl(
        &self,
        key: &str,
        value: serde_json::Value,
        ttl: std::time::Duration,
    ) -> Pin<Box<dyn Future<Output = Result<bool, StoreError>> + Send + '_>> {
        let key = key.to_owned();
        Box::pin(async move {
            let expires = now_ms() + ttl.as_secs_f64() * 1000.0;
            let claimed = self.claim(&key, serialize(&value)?, Some(expires)).await?;
            // The reservation's own expiry may have passed while the statement ran.
            Ok(claimed && expires > now_ms())
        })
    }
}

/// An identifier, optionally schema-qualified: `[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)?`.
fn is_valid_table(table: &str) -> bool {
    let identifier = |part: &str| {
        let mut chars = part.chars();
        chars
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
    };
    let parts: Vec<&str> = table.split('.').collect();
    parts.len() <= 2 && parts.into_iter().all(identifier)
}

/// Rewrites `?` placeholders as `$1`, `$2`, ... (the statements here hold no `?` literals).
fn number_placeholders(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 8);
    let mut index = 0;
    for c in text.chars() {
        if c == '?' {
            index += 1;
            out.push('$');
            out.push_str(&index.to_string());
        } else {
            out.push(c);
        }
    }
    out
}

fn now_ms() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64() * 1000.0)
        .unwrap_or(0.0)
}

fn text(value: &str) -> SqlParam {
    SqlParam::Text(value.to_owned())
}

fn serialize(value: &serde_json::Value) -> Result<String, StoreError> {
    serde_json::to_string(value).map_err(|e| StoreError::Serialization(e.to_string()))
}

fn parse(raw: &str) -> Result<serde_json::Value, StoreError> {
    serde_json::from_str(raw).map_err(|e| StoreError::Serialization(e.to_string()))
}

#[cfg(feature = "postgres-store")]
impl SqlDriver for tokio_postgres::Client {
    fn dialect(&self) -> SqlDialect {
        SqlDialect::Postgres
    }

    fn query<'a>(
        &'a self,
        sql: &'a str,
        params: &'a [SqlParam],
    ) -> Pin<Box<dyn Future<Output = Result<Vec<String>, StoreError>> + Send + 'a>> {
        Box::pin(async move {
            let params: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> = params
                .iter()
                .map(|param| match param {
                    SqlParam::Text(value) => value as &(dyn tokio_postgres::types::ToSql + Sync),
                    SqlParam::Float(value) => value,
                })
                .collect();
            let rows = tokio_postgres::Client::query(self, sql, &params)
                .await
                .map_err(|e| StoreError::Internal(e.to_string()))?;
            rows.iter()
                .map(|row| row.try_get::<_, String>(0))
                .collect::<Result<_, _>>()
                .map_err(|e| StoreError::Internal(e.to_string()))
        })
    }
}

/// Runs each statement on Tokio's blocking pool, so a busy database file (rusqlite's
/// 5 s busy timeout) or a contended connection never stalls an async worker thread.
/// Needs a Tokio runtime.
#[cfg(feature = "sqlite-store")]
impl SqlDriver for std::sync::Arc<std::sync::Mutex<rusqlite::Connection>> {
    fn dialect(&self) -> SqlDialect {
        SqlDialect::Sqlite
    }

    fn query<'a>(
        &'a self,
        sql: &'a str,
        params: &'a [SqlParam],
    ) -> Pin<Box<dyn Future<Output = Result<Vec<String>, StoreError>> + Send + 'a>> {
        let connection = std::sync::Arc::clone(self);
        let sql = sql.to_owned();
        let params = params.to_vec();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || sqlite_query(&connection, &sql, params))
                .await
                .map_err(|e| StoreError::Internal(format!("SQLite task failed: {e}")))?
        })
    }
}

#[cfg(feature = "sqlite-store")]
fn sqlite_query(
    connection: &std::sync::Mutex<rusqlite::Connection>,
    sql: &str,
    params: Vec<SqlParam>,
) -> Result<Vec<String>, StoreError> {
    let connection = connection
        .lock()
        .map_err(|_| StoreError::Internal("SQLite connection lock poisoned".into()))?;
    let mut statement = connection.prepare_cached(sql).map_err(sqlite_error)?;
    let params = params.into_iter().map(|param| match param {
        SqlParam::Text(value) => rusqlite::types::Value::Text(value),
        SqlParam::Float(Some(value)) => rusqlite::types::Value::Real(value),
        SqlParam::Float(None) => rusqlite::types::Value::Null,
    });
    let rows = statement
        .query_map(rusqlite::params_from_iter(params), |row| {
            row.get::<_, String>(0)
        })
        .map_err(sqlite_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sqlite_error)?;
    Ok(rows)
}

#[cfg(feature = "sqlite-store")]
fn sqlite_error(error: rusqlite::Error) -> StoreError {
    StoreError::Internal(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::{Arc, Mutex};
    #[cfg(any(feature = "sqlite-store", feature = "postgres-store"))]
    use std::time::Duration;

    type Respond = Box<dyn Fn(&str) -> Result<Vec<String>, StoreError> + Send + Sync>;

    /// Records statements and answers them with `respond`.
    struct FakeDriver {
        dialect: SqlDialect,
        seen: Mutex<Vec<String>>,
        respond: Respond,
    }

    impl FakeDriver {
        fn new(
            dialect: SqlDialect,
            respond: impl Fn(&str) -> Result<Vec<String>, StoreError> + Send + Sync + 'static,
        ) -> Self {
            Self {
                dialect,
                seen: Mutex::new(Vec::new()),
                respond: Box::new(respond),
            }
        }
    }

    impl SqlDriver for FakeDriver {
        fn dialect(&self) -> SqlDialect {
            self.dialect
        }

        fn query<'a>(
            &'a self,
            sql: &'a str,
            _params: &'a [SqlParam],
        ) -> Pin<Box<dyn Future<Output = Result<Vec<String>, StoreError>> + Send + 'a>> {
            self.seen.lock().unwrap().push(sql.to_owned());
            Box::pin(std::future::ready((self.respond)(sql)))
        }
    }

    #[tokio::test]
    async fn sql_store_numbers_placeholders_for_postgres_only() {
        for (dialect, values) in [
            (SqlDialect::Postgres, "VALUES ($1, $2, $3)"),
            (SqlDialect::Sqlite, "VALUES (?, ?, ?)"),
        ] {
            let store =
                SqlStore::new(FakeDriver::new(dialect, |_| Ok(vec![]))).with_create_table(false);
            store.put("k", json!(1)).await.unwrap();
            let seen = store.driver.seen.lock().unwrap();
            assert_eq!(seen.len(), 1);
            assert!(seen[0].contains(values), "{}", seen[0]);
        }
    }

    #[test]
    fn sql_store_rejects_table_names_that_are_not_identifiers() {
        for table in [
            "store; DROP TABLE x",
            "",
            "1store",
            "a.b.c",
            "a.",
            "\"quoted\"",
        ] {
            let result = SqlStore::new(FakeDriver::new(SqlDialect::Sqlite, |_| Ok(vec![])))
                .with_table(table);
            let error = result.err().expect(table).to_string();
            assert!(error.contains("Invalid SQL store table name"), "{error}");
        }
        for table in ["custom", "_store", "billing.mppx_store"] {
            assert!(
                SqlStore::new(FakeDriver::new(SqlDialect::Sqlite, |_| Ok(vec![])))
                    .with_table(table)
                    .is_ok()
            );
        }
    }

    #[tokio::test]
    async fn sql_store_treats_a_failed_create_table_as_ready_when_the_table_exists() {
        let store = SqlStore::new(FakeDriver::new(SqlDialect::Sqlite, |sql| {
            if sql.starts_with("CREATE") {
                Err(StoreError::Internal("duplicate key value".into()))
            } else {
                Ok(vec![])
            }
        }));
        assert_eq!(store.get("k").await.unwrap(), None);
        assert_eq!(store.get("k").await.unwrap(), None);
        // CREATE and its probe once, then two reads.
        assert_eq!(store.driver.seen.lock().unwrap().len(), 4);
    }

    #[tokio::test]
    async fn sql_store_retries_table_creation_after_a_failure() {
        let fail = Arc::new(Mutex::new(true));
        let flag = fail.clone();
        let store = SqlStore::new(FakeDriver::new(SqlDialect::Sqlite, move |_| {
            if *flag.lock().unwrap() {
                Err(StoreError::Internal("offline".into()))
            } else {
                Ok(vec![])
            }
        }));
        let error = store.get("k").await.unwrap_err().to_string();
        assert!(error.contains("offline"), "{error}");
        *fail.lock().unwrap() = false;
        assert_eq!(store.get("k").await.unwrap(), None);
        assert!(store.driver.seen.lock().unwrap()[2].starts_with("CREATE"));
    }

    // ==================== Shared suite ====================

    #[cfg(any(feature = "sqlite-store", feature = "postgres-store"))]
    /// Runs every behavior check against stores from `make`, each on its own table.
    async fn run_suite<D, F, Fut>(make: F)
    where
        D: SqlDriver,
        F: Fn(&'static str) -> Fut,
        Fut: Future<Output = SqlStore<D>>,
    {
        get_put_delete(&make("get_put_delete").await).await;
        compare_exchange(&make("compare_exchange").await).await;
        put_if_absent(&make("put_if_absent").await).await;
        expiring_claims(&make("expiring_claims").await).await;
        concurrent_claims(&make("concurrent_claims").await).await;
        purge_expired(&make("purge_expired").await).await;
    }

    #[cfg(any(feature = "sqlite-store", feature = "postgres-store"))]
    async fn purge_expired<D: SqlDriver>(store: &SqlStore<D>) {
        store.put("permanent", json!(1)).await.unwrap();
        assert!(store
            .put_if_absent_with_ttl("short", json!(2), Duration::from_millis(100))
            .await
            .unwrap());
        assert!(store
            .put_if_absent_with_ttl("live", json!(3), Duration::from_secs(60))
            .await
            .unwrap());
        assert_eq!(store.purge_expired().await.unwrap(), 0);
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(store.purge_expired().await.unwrap(), 1);
        assert_eq!(store.get("permanent").await.unwrap(), Some(json!(1)));
        assert_eq!(store.get("live").await.unwrap(), Some(json!(3)));
        assert_eq!(store.purge_expired().await.unwrap(), 0);
    }

    #[cfg(any(feature = "sqlite-store", feature = "postgres-store"))]
    async fn get_put_delete(store: &dyn Store) {
        assert_eq!(store.get("k").await.unwrap(), None);
        store
            .put("k", json!({"amount": "1", "n": 2}))
            .await
            .unwrap();
        assert_eq!(
            store.get("k").await.unwrap(),
            Some(json!({"amount": "1", "n": 2}))
        );
        store.put("k", json!("v2")).await.unwrap();
        assert_eq!(store.get("k").await.unwrap(), Some(json!("v2")));
        store.delete("k").await.unwrap();
        assert_eq!(store.get("k").await.unwrap(), None);
        store.delete("k").await.unwrap();
    }

    #[cfg(any(feature = "sqlite-store", feature = "postgres-store"))]
    async fn compare_exchange(store: &dyn Store) {
        // Absent key: (None, None) reports absence, (None, Some) inserts once.
        assert!(store.compare_exchange("k", None, None).await.unwrap());
        assert!(store
            .compare_exchange("k", None, Some(json!(1)))
            .await
            .unwrap());
        assert!(!store
            .compare_exchange("k", None, Some(json!(2)))
            .await
            .unwrap());
        assert!(!store.compare_exchange("k", None, None).await.unwrap());
        assert_eq!(store.get("k").await.unwrap(), Some(json!(1)));

        // Swap succeeds only from the expected value.
        assert!(store
            .compare_exchange("k", Some(json!(1)), Some(json!(2)))
            .await
            .unwrap());
        assert!(!store
            .compare_exchange("k", Some(json!(1)), Some(json!(3)))
            .await
            .unwrap());
        assert_eq!(store.get("k").await.unwrap(), Some(json!(2)));

        // Expected value on an absent key conflicts.
        assert!(!store
            .compare_exchange("missing", Some(json!(1)), Some(json!(2)))
            .await
            .unwrap());
        assert_eq!(store.get("missing").await.unwrap(), None);

        // Delete by swap.
        assert!(!store
            .compare_exchange("k", Some(json!(1)), None)
            .await
            .unwrap());
        assert!(store
            .compare_exchange("k", Some(json!(2)), None)
            .await
            .unwrap());
        assert_eq!(store.get("k").await.unwrap(), None);

        // An equal value stored with another key order still matches.
        store.put("obj", json!({"b": 1, "a": 2})).await.unwrap();
        assert!(store
            .compare_exchange("obj", Some(json!({"a": 2, "b": 1})), Some(json!({"c": 3})))
            .await
            .unwrap());
        assert_eq!(store.get("obj").await.unwrap(), Some(json!({"c": 3})));
    }

    #[cfg(any(feature = "sqlite-store", feature = "postgres-store"))]
    async fn put_if_absent(store: &dyn Store) {
        assert!(store.put_if_absent("k", json!("first")).await.unwrap());
        assert!(!store.put_if_absent("k", json!("second")).await.unwrap());
        assert_eq!(store.get("k").await.unwrap(), Some(json!("first")));

        // A reservation never evicts a permanent entry.
        assert!(!store
            .put_if_absent_with_ttl("k", json!("claim"), Duration::from_secs(60))
            .await
            .unwrap());
        assert_eq!(store.get("k").await.unwrap(), Some(json!("first")));
    }

    #[cfg(any(feature = "sqlite-store", feature = "postgres-store"))]
    async fn expiring_claims(store: &dyn Store) {
        let ttl = Duration::from_millis(300);
        assert!(store
            .put_if_absent_with_ttl("n", json!(1), ttl)
            .await
            .unwrap());
        // Refused while live, and the live claim is kept.
        assert!(!store
            .put_if_absent_with_ttl("n", json!(2), ttl)
            .await
            .unwrap());
        assert!(!store.put_if_absent("n", json!(2)).await.unwrap());
        assert!(!store
            .compare_exchange("n", None, Some(json!(2)))
            .await
            .unwrap());
        assert_eq!(store.get("n").await.unwrap(), Some(json!(1)));

        tokio::time::sleep(Duration::from_millis(400)).await;
        // Expired: reads as missing, no longer matches, and can be claimed again.
        assert_eq!(store.get("n").await.unwrap(), None);
        assert!(!store
            .compare_exchange("n", Some(json!(1)), Some(json!(3)))
            .await
            .unwrap());
        assert!(store
            .put_if_absent_with_ttl("n", json!(4), Duration::from_secs(60))
            .await
            .unwrap());
        assert_eq!(store.get("n").await.unwrap(), Some(json!(4)));

        // Plain inserts also replace an expired claim, and keep it permanently.
        assert!(store
            .put_if_absent_with_ttl("m", json!(1), ttl)
            .await
            .unwrap());
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert!(store.put_if_absent("m", json!(2)).await.unwrap());
        assert!(!store
            .put_if_absent_with_ttl("m", json!(3), ttl)
            .await
            .unwrap());
        assert_eq!(store.get("m").await.unwrap(), Some(json!(2)));

        // A claim that expires before it is recorded is refused.
        assert!(!store
            .put_if_absent_with_ttl("zero", json!(1), Duration::ZERO)
            .await
            .unwrap());
    }

    #[cfg(any(feature = "sqlite-store", feature = "postgres-store"))]
    async fn concurrent_claims(store: &dyn Store) {
        let results = futures_util::future::join_all(
            (0..20)
                .map(|i| store.put_if_absent_with_ttl("nonce", json!(i), Duration::from_secs(60))),
        )
        .await;
        let claimed = results.into_iter().filter(|r| *r.as_ref().unwrap()).count();
        assert_eq!(claimed, 1);
    }

    // ==================== SQLite ====================

    #[cfg(feature = "sqlite-store")]
    fn sqlite_store() -> SqlStore<Arc<Mutex<rusqlite::Connection>>> {
        SqlStore::new(Arc::new(Mutex::new(
            rusqlite::Connection::open_in_memory().unwrap(),
        )))
    }

    #[cfg(feature = "sqlite-store")]
    #[tokio::test]
    async fn sqlite_store_suite() {
        run_suite(|table| async move { sqlite_store().with_table(table).unwrap() }).await;
        // The default and a schema-qualified table.
        get_put_delete(&sqlite_store()).await;
        get_put_delete(&sqlite_store().with_table("main.custom_store").unwrap()).await;
    }

    #[cfg(feature = "sqlite-store")]
    #[tokio::test]
    async fn sqlite_store_leaves_the_table_to_migrations_without_create_table() {
        assert!(sqlite_store()
            .with_create_table(false)
            .get("k")
            .await
            .is_err());
    }

    // ==================== Postgres ====================

    /// Postgres DSN for the tests below, which skip when it is unset.
    #[cfg(feature = "postgres-store")]
    const POSTGRES_URL_ENV: &str = "MPP_TEST_POSTGRES_URL";

    #[cfg(feature = "postgres-store")]
    async fn postgres_client() -> Option<tokio_postgres::Client> {
        let Ok(url) = std::env::var(POSTGRES_URL_ENV) else {
            eprintln!("skipping: {POSTGRES_URL_ENV} not set");
            return None;
        };
        let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
            .await
            .expect("connect to Postgres");
        tokio::spawn(connection);
        Some(client)
    }

    #[cfg(feature = "postgres-store")]
    #[tokio::test]
    async fn postgres_store_suite() {
        let Some(admin) = postgres_client().await else {
            return;
        };
        let schema = format!("mpp_test_{}", uuid::Uuid::new_v4().simple());
        admin
            .batch_execute(&format!("CREATE SCHEMA {schema}"))
            .await
            .unwrap();
        let schema_ref = schema.as_str();
        run_suite(|table| async move {
            SqlStore::new(postgres_client().await.unwrap())
                .with_table(format!("{schema_ref}.{table}"))
                .unwrap()
        })
        .await;

        // Separate connections race on separate backends: claims stay exclusive
        // and concurrent stores create the same table without failing.
        let stores: Vec<_> = futures_util::future::join_all((0..10).map(|_| async move {
            SqlStore::new(postgres_client().await.unwrap())
                .with_table(format!("{schema_ref}.shared"))
                .unwrap()
        }))
        .await;
        let results =
            futures_util::future::join_all(stores.iter().enumerate().map(|(i, s)| {
                s.put_if_absent_with_ttl("nonce", json!(i), Duration::from_secs(60))
            }))
            .await;
        assert_eq!(
            results.into_iter().filter(|r| *r.as_ref().unwrap()).count(),
            1
        );
        let results = futures_util::future::join_all(
            stores
                .iter()
                .map(|s| s.compare_exchange("cas", None, Some(json!(1)))),
        )
        .await;
        assert_eq!(
            results.into_iter().filter(|r| *r.as_ref().unwrap()).count(),
            1
        );

        let without_create = SqlStore::new(postgres_client().await.unwrap())
            .with_table(format!("{schema}.missing"))
            .unwrap()
            .with_create_table(false);
        assert!(without_create.get("k").await.is_err());

        admin
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await
            .unwrap();
    }
}
