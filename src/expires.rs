//! Expiration time helpers.
//!
//! Convenience functions for generating ISO 8601 expiration timestamps,
//! matching the `Expires` module in the TypeScript SDK.
//!
//! # Examples
//!
//! ```
//! use mpp::expires;
//!
//! let five_min = expires::minutes(5);
//! let one_hour = expires::hours(1);
//! let one_week = expires::weeks(1);
//! ```

use time::format_description::well_known::Iso8601;
use time::{Duration, OffsetDateTime};

/// Returns an ISO 8601 datetime string `n` seconds from now.
pub fn seconds(n: u64) -> String {
    offset(Duration::seconds(n as i64))
}

/// Returns an ISO 8601 datetime string `n` minutes from now.
pub fn minutes(n: u64) -> String {
    offset(Duration::minutes(n as i64))
}

/// Returns an ISO 8601 datetime string `n` hours from now.
pub fn hours(n: u64) -> String {
    offset(Duration::hours(n as i64))
}

/// Returns an ISO 8601 datetime string `n` days from now.
pub fn days(n: u64) -> String {
    offset(Duration::days(n as i64))
}

/// Returns an ISO 8601 datetime string `n` weeks from now.
pub fn weeks(n: u64) -> String {
    offset(Duration::weeks(n as i64))
}

/// Returns an ISO 8601 datetime string `n` months (30 days each) from now.
pub fn months(n: u64) -> String {
    offset(Duration::days(n as i64 * 30))
}

/// Returns an ISO 8601 datetime string `n` years (365 days each) from now.
pub fn years(n: u64) -> String {
    offset(Duration::days(n as i64 * 365))
}

fn offset(duration: Duration) -> String {
    let dt = OffsetDateTime::now_utc() + duration;
    dt.format(&Iso8601::DEFAULT)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_minutes_format() {
        let result = minutes(5);
        // Should be a valid ISO 8601 string
        assert!(result.contains('T'));
        assert!(result.len() > 10);
    }

    #[test]
    fn test_hours_is_later_than_minutes() {
        let m = minutes(1);
        let h = hours(1);
        // hours(1) should be after minutes(1)
        assert!(h > m);
    }

    #[test]
    fn test_days() {
        let result = days(7);
        assert!(result.contains('T'));
    }

    #[test]
    fn test_weeks() {
        let result = weeks(1);
        assert!(result.contains('T'));
    }

    #[test]
    fn test_months() {
        let result = months(1);
        assert!(result.contains('T'));
    }

    #[test]
    fn test_years() {
        let result = years(1);
        assert!(result.contains('T'));
    }

    #[test]
    fn test_seconds() {
        let result = seconds(30);
        assert!(result.contains('T'));
    }
}
