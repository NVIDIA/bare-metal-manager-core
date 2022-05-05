use log::LevelFilter;
use rpc::v0 as rpc;
use sqlx::Postgres;

use carbide::{
    db::{
        AddressSelectionStrategy, Domain, Machine, MachineInterface, NetworkSegment, NewDomain,
        NewNetworkPrefix, NewNetworkSegment, NewVpc, Tag, TagAssociation, TagCreate, TagDelete,
        TagTargetKind, TagsList,
    },
    CarbideResult,
};

mod common;

async fn test_create(
    txn: &mut sqlx::Transaction<'_, Postgres>,
    slug: String,
    name: String,
) -> CarbideResult<rpc::TagResult> {
    let request = TagCreate {
        tag: Some(Tag {
            id: None,
            slug: slug.to_owned(),
            name: Some(name.to_owned()),
        }),
    };

    request.create(txn).await
}

async fn test_delete(txn: &mut sqlx::Transaction<'_, Postgres>) -> CarbideResult<rpc::TagResult> {
    let request = TagDelete {
        tag: Some(Tag {
            id: None,
            slug: "testtag".to_string(),
            name: None,
        }),
    };
    request.delete(txn).await
}

async fn create_machine(txn: &mut sqlx::Transaction<'_, Postgres>) -> Machine {
    let my_domain = "dwrt.com";

    let _new_domain: CarbideResult<Domain> = NewDomain {
        name: my_domain.to_string(),
    }
    .persist(txn)
    .await;

    let domain = Domain::find_by_name(txn, my_domain.to_string())
        .await
        .expect("Could not find domain in DB");

    let vpc = NewVpc {
        name: "Test VPC".to_string(),
        organization: Some(uuid::Uuid::new_v4()),
    }
    .persist(txn)
    .await
    .expect("Unable to create VPC");

    let segment: NetworkSegment = NewNetworkSegment {
        name: "integration_test".to_string(),
        subdomain_id: Some(domain).unwrap().map(|d| d.id().to_owned()),
        mtu: Some(1500i32),
        vpc_id: Some(vpc.id),

        prefixes: vec![
            NewNetworkPrefix {
                prefix: "2001:db8:f::/64".parse().unwrap(),
                gateway: None,
                num_reserved: 100,
            },
            NewNetworkPrefix {
                prefix: "192.0.2.0/24".parse().unwrap(),
                gateway: "192.0.2.1".parse().ok(),
                num_reserved: 2,
            },
        ],
    }
    .persist(txn)
    .await
    .expect("Unable to create network segment");

    let test_mac = "ff:ff:ff:ff:ff:ff".parse().unwrap();

    let new_interface = MachineInterface::create(
        txn,
        &segment,
        &test_mac,
        None,
        "foobar".to_string(),
        true,
        AddressSelectionStrategy::Automatic,
    )
    .await
    .expect("Unable to create interface");

    let new_machine = Machine::create(txn, new_interface)
        .await
        .expect("Unable to create machine");

    new_machine
}

async fn test_list(
    txn: &mut sqlx::Transaction<'_, Postgres>,
) -> CarbideResult<rpc::TagsListResult> {
    Tag::list_all(txn).await
}

#[tokio::test]
async fn tag_create_and_list() {
    pretty_env_logger::formatted_timed_builder()
        .filter_level(LevelFilter::Error)
        .init();

    let pool = common::TestDatabaseManager::new()
        .await
        .expect("Could not create database manager")
        .pool;

    {
        let mut txn = pool
            .begin()
            .await
            .expect("Unable to create transaction on database pool");
        {
            let ret_val =
                test_create(&mut txn, "testtag".to_string(), "Test Tag".to_string()).await;
            assert!(ret_val.unwrap().result);
        }
        txn.commit().await.unwrap();
    }

    {
        let mut txn = pool
            .begin()
            .await
            .expect("Unable to create transaction on database pool");
        let ret_val = test_list(&mut txn).await;
        assert!(ret_val.is_ok());

        let ret_val = ret_val.unwrap();
        assert_eq!(ret_val.tags[0].slug, "testtag".to_string());
        assert_eq!(
            ret_val.tags[0].name.to_owned().unwrap(),
            "Test Tag".to_string()
        );
    }
}

#[tokio::test]
async fn tag_deletion() {
    let pool = common::TestDatabaseManager::new()
        .await
        .expect("Could not create database manager")
        .pool;

    // Create tag first to delete.
    {
        let mut txn = pool
            .begin()
            .await
            .expect("Unable to create transaction on database pool");
        {
            let ret_val =
                test_create(&mut txn, "testtag".to_string(), "Test Tag".to_string()).await;
            assert!(ret_val.unwrap().result);
        }
        txn.commit().await.unwrap();
    }

    // Delete it now.
    {
        let mut txn = pool
            .begin()
            .await
            .expect("Unable to create transaction on database pool");
        {
            let ret_val = test_delete(&mut txn).await;
            assert!(ret_val.unwrap().result);
        }
        txn.commit().await.unwrap();
    }
}

#[tokio::test]
async fn tag_assign_and_remove() {
    let pool = common::TestDatabaseManager::new()
        .await
        .expect("Could not create database manager")
        .pool;

    // Create tag first to delete.
    let mut txn = pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");
    let machine = create_machine(&mut txn).await;
    txn.commit().await.unwrap();

    let mut txn = pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");
    {
        let ret_val = test_create(&mut txn, "testtag".to_string(), "Test Tag".to_string()).await;
        assert!(ret_val.unwrap().result);
    }
    txn.commit().await.unwrap();

    let mut txn = pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");
    let testassociation = TagAssociation {
        tag_id: None,
        slug: Some("testtag".to_string()),
        target: *machine.id(),
        target_kind: TagTargetKind::Machine,
    };

    let result = testassociation.assign(&mut txn).await;
    txn.commit().await.unwrap();
    assert!(result.unwrap().result);

    let mut txn = pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");
    let testassociation = TagAssociation {
        tag_id: None,
        slug: Some("testtag".to_string()),
        target: *machine.id(),
        target_kind: TagTargetKind::Machine,
    };

    let result = testassociation.remove(&mut txn).await;
    txn.commit().await.unwrap();
    assert!(result.unwrap().result);
}

#[tokio::test]
async fn test_set_tags() {
    let pool = common::TestDatabaseManager::new()
        .await
        .expect("Could not create database manager")
        .pool;

    // Create tag first to delete.
    let mut txn = pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");
    let machine = create_machine(&mut txn).await;
    txn.commit().await.unwrap();

    let mut txn = pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");
    {
        let ret_val = test_create(&mut txn, "testtag".to_string(), "Test Tag".to_string()).await;
        assert!(ret_val.unwrap().result);
        let ret_val = test_create(&mut txn, "testtag1".to_string(), "Test Tag".to_string()).await;
        assert!(ret_val.unwrap().result);
    }
    txn.commit().await.unwrap();

    let mut txn = pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");
    let testlist = TagsList {
        slugs: vec!["testtag".to_string(), "testtag1".to_string()],
        target: *machine.id(),
        target_kind: TagTargetKind::Machine,
    };

    let result = testlist.assign(&mut txn).await;
    txn.commit().await.unwrap();
    assert!(result.unwrap().result);
}
