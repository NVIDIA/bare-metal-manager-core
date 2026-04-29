use super::racks::{Rack, Racks};
use crate::client::NiccClient;
use crate::error::RvsError;

/// Fetch all racks from NICC, hydrating each with its compute tray data.
///
/// Two-step: first list all racks (IDs + states), then fetch machine details
/// for each rack's compute trays in parallel-friendly chunks.
pub async fn fetch_racks(nicc: &NiccClient) -> Result<Racks, RvsError> {
    let rack_data = nicc.get_racks().await?;
    let mut inner = Vec::with_capacity(rack_data.len());
    for rd in rack_data {
        let trays = nicc.get_machines(&rd).await?;
        inner.push(Rack::new(rd.id, rd.state, trays));
    }
    Ok(Racks { inner })
}
