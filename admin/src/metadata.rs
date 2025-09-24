use rpc::Metadata;

pub(crate) fn get_nice_labels_from_rpc_metadata(metadata: &Option<Metadata>) -> Vec<String> {
    let default_metadata = Default::default();
    metadata
        .as_ref()
        .unwrap_or(&default_metadata)
        .labels
        .iter()
        .map(|label| {
            let key = &label.key;
            let value = label.value.clone().unwrap_or_default();
            format!("\"{key}:{value}\"")
        })
        .collect()
}
