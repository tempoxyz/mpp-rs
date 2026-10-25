//! MPP service directories such as [mpp.dev](https://mpp.dev/services).

use serde::Deserialize;

use crate::error::{MppError, ResultExt};

/// The directory of MPP services listed on mpp.dev.
pub const MPP_DIRECTORY_URL: &str = "https://mpp.dev/api/services";

#[derive(Deserialize)]
struct Directory {
    services: Vec<Service>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Service {
    service_url: String,
}

/// Fetch the service URLs listed in an MPP service directory such as
/// [`MPP_DIRECTORY_URL`], for example to build an
/// [`AcceptPaymentPolicy::Origins`](super::AcceptPaymentPolicy::Origins) that
/// pays only listed services.
pub async fn service_urls(
    client: &reqwest::Client,
    directory: &str,
) -> Result<Vec<String>, MppError> {
    let directory: Directory = client
        .get(directory)
        .send()
        .await
        .mpp_http("failed to fetch the MPP service directory")?
        .error_for_status()
        .mpp_http("failed to fetch the MPP service directory")?
        .json()
        .await
        .mpp_http("invalid MPP service directory")?;
    Ok(directory
        .services
        .into_iter()
        .map(|service| service.service_url)
        .collect())
}
