//! Identity rejection statuses, as mppx's `Identity.Status`.

use super::RejectionStatus;

/// Rejected statuses from highest to lowest precedence.
///
/// When several verifiers reject (or every [`any_of`](super::any_of) member
/// does), the outcome whose status comes first here decides the status and
/// reason.
pub const PRECEDENCE: [RejectionStatus; 4] = [
    RejectionStatus::Forbidden,
    RejectionStatus::Unavailable,
    RejectionStatus::Invalid,
    RejectionStatus::Missing,
];

/// The HTTP status code of each rejected status.
pub fn code(status: RejectionStatus) -> u16 {
    status.code().as_u16()
}
