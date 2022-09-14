use std::sync::Once;

use kube::api::PostParams;
use kube::{Api, Client};
use log::LevelFilter;

use carbide::db::constants::FORGE_KUBE_NAMESPACE;
use carbide::vpc_resources::leaf;

static INIT: Once = Once::new();

fn setup() {
    INIT.call_once(init_logger);
}

fn init_logger() {
    pretty_env_logger::formatted_timed_builder()
        .filter_level(LevelFilter::Error)
        .init();
}

#[tokio::test]
#[ignore]
async fn create_leaf_in_kube() {
    setup();

    let client = Client::try_default()
        .await
        .expect("Unable to connect to kubernetes");
    let namespace = FORGE_KUBE_NAMESPACE;

    let leafname = uuid::Uuid::new_v4().to_string();

    let leafs: Api<leaf::Leaf> = Api::namespaced(client.to_owned(), namespace);
    let leaf_spec = leaf::Leaf::new(
        leafname.as_str(),
        leaf::LeafSpec {
            control: Some(leaf::LeafControl {
                maintenance_mode: Some(true),
                management_ip: Some("4.3.2.1".to_string()),
                vendor: None,
            }),
            host_admin_i_ps: None,
            host_interfaces: None,
        },
    );

    leafs
        .create(&PostParams::default(), &leaf_spec)
        .await
        .expect("Could not create leaf");

    let leaf = leafs
        .get(leafname.as_str())
        .await
        .expect("Could not retrieve new leaf");

    assert_eq!(
        leaf.spec.control.unwrap().management_ip.unwrap(),
        "4.3.2.1".to_string()
    );

    assert!(leaf.status.is_none())
}
