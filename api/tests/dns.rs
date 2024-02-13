use carbide::db::{machine_interface::MachineInterface, machine_topology::MachineTopology};
use common::api_fixtures::{create_managed_host, create_test_env};
use const_format::concatcp;
use rpc::forge::{forge_server::Forge, DhcpDiscovery};
use sqlx::{Postgres, Row};

// These should probably go in a common place for both
// this and tests/integration/api_server.rs to share.
const DOMAIN_NAME: &str = "dwrt1.com";
const DNS_ADM_SUBDOMAIN: &str = concatcp!("adm.", DOMAIN_NAME);
const DNS_BMC_SUBDOMAIN: &str = concatcp!("bmc.", DOMAIN_NAME);

pub mod common;

#[ctor::ctor]
fn setup() {
    common::test_logging::init();
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment",))]
async fn test_dns(pool: sqlx::PgPool) {
    let env = create_test_env(pool.clone()).await;
    let api = &env.api;

    // Database should have 0 rows in the dns_records view.
    assert_eq!(0, get_dns_record_count(&pool).await);

    let mac_address = "FF:FF:FF:FF:FF:FF".to_string();
    let interface1 = api
        .discover_dhcp(tonic::Request::new(DhcpDiscovery {
            mac_address: mac_address.clone(),
            relay_address: "192.0.2.1".to_string(),
            link_address: None,
            vendor_string: None,
            circuit_id: None,
            remote_id: None,
        }))
        .await
        .unwrap()
        .into_inner();

    let fqdn1 = interface1.fqdn;
    let ip1 = interface1.address;
    let mac_address = "F1:FF:FF:FF:FF:FF".to_string();
    let interface2 = api
        .discover_dhcp(tonic::Request::new(DhcpDiscovery {
            mac_address: mac_address.clone(),
            relay_address: "192.0.2.1".to_string(),
            link_address: None,
            vendor_string: None,
            circuit_id: None,
            remote_id: None,
        }))
        .await
        .unwrap()
        .into_inner();

    let fqdn2 = interface2.fqdn;
    let ip2 = interface2.address;

    let dns_record = api
        .lookup_record(tonic::Request::new(rpc::forge::dns_message::DnsQuestion {
            q_name: Some(fqdn1 + "."),
            q_type: Some(1),
            q_class: Some(1),
        }))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(
        ip1.split('/').collect::<Vec<&str>>()[0],
        &dns_record.rrs[0].rdata.clone().unwrap()
    );

    let dns_record = api
        .lookup_record(tonic::Request::new(rpc::forge::dns_message::DnsQuestion {
            q_name: Some(fqdn2 + "."),
            q_type: Some(1),
            q_class: Some(1),
        }))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(
        ip2.split('/').collect::<Vec<&str>>()[0],
        &dns_record.rrs[0].rdata.clone().unwrap()
    );

    // Create a managed host to make sure that the MachineId DNS
    // records for the Host and DPU are created + end up in the
    // dns_records view.
    let (host_id, dpu_id) = create_managed_host(&env).await;

    // And now check to make sure the DNS records exist and,
    // of course, that they are correct.
    let machine_ids = [host_id, dpu_id];
    for machine_id in machine_ids.iter() {
        let mut txn = pool.begin().await.unwrap();

        // First, check the BMC record by querying the MachineTopology
        // data for the current machine ID.
        tracing::info!(machine_id = %machine_id, subdomain = %DNS_BMC_SUBDOMAIN, "Checking BMC record");
        let topologies = MachineTopology::find_by_machine_ids(&mut txn, &[machine_id.clone()])
            .await
            .unwrap();
        let topology = &topologies.get(machine_id).unwrap()[0];
        let bmc_record = api
            .lookup_record(tonic::Request::new(rpc::forge::dns_message::DnsQuestion {
                q_name: Some(format!("{}.{}.", machine_id, DNS_BMC_SUBDOMAIN)),
                q_type: Some(1),
                q_class: Some(1),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            topology.topology().bmc_info.ip.as_ref().unwrap().as_str(),
            &bmc_record.rrs[0].rdata.clone().unwrap()
        );

        // And now check the ADM (Admin IP) record by querying the
        // MachineInterface data for the given machineID.
        tracing::info!(machine_id = %machine_id, subdomain = %DNS_ADM_SUBDOMAIN, "Checking ADM record");
        let interface =
            MachineInterface::get_machine_interface_primary(&machine_id.clone(), &mut txn)
                .await
                .unwrap();
        let adm_record = api
            .lookup_record(tonic::Request::new(rpc::forge::dns_message::DnsQuestion {
                q_name: Some(format!("{}.{}.", machine_id, DNS_ADM_SUBDOMAIN)),
                q_type: Some(1),
                q_class: Some(1),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            format!("{}", interface.addresses()[0].address).as_str(),
            &adm_record.rrs[0].rdata.clone().unwrap()
        );
    }

    // Database should ultimately have 10 rows:
    // - 4x from the DHCP discovery testing.
    // - 6x from the managed host testing.
    //      - 2x fancy names
    //      - 2x admin machine ID names
    //      - 2x bmc machine ID names
    assert_eq!(10, get_dns_record_count(&pool).await);
}

// Get the current number of rows in the dns_records view,
// which is expected to start at 0, and then progress, as
// the test continues.
//
// TODO(chet): Find a common place for this and the same exact
// function in api-test/tests/integration/main.rs to exist, instead
// of it being in two places.
pub async fn get_dns_record_count(pool: &sqlx::Pool<Postgres>) -> i64 {
    let mut txn = pool.begin().await.unwrap();
    let query = "SELECT COUNT(*) as row_cnt FROM dns_records";
    let rows = sqlx::query::<_>(query).fetch_one(&mut *txn).await.unwrap();
    rows.try_get("row_cnt").unwrap()
}
