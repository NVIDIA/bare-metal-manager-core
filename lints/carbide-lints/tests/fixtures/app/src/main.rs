use std::ops::DerefMut;

use sqlx::pool::PoolConnection;
use sqlx::{Executor, PgConnection, PgTransaction, Postgres};

async fn good_db_related() {
    let mut txn = make_transaction();
    db::actually_use_txn(txn.deref_mut()).await;
    good_outer_db_wrapper(&mut txn).await;
    txn.commit().await.unwrap();
}

async fn good_db_related_tuples() {
    let (mut txn, ..) = make_transaction_tuple_1();
    good_outer_db_wrapper(&mut txn).await;
    txn.commit().await.unwrap();

    let (_, mut txn, _) = make_transaction_tuple_2();
    good_outer_db_wrapper(&mut txn).await;
    txn.commit().await.unwrap();

    let (.., mut txn) = make_transaction_tuple_3();
    good_outer_db_wrapper(&mut txn).await;
    txn.commit().await.unwrap();
}

async fn bad_unrelated_tuples() {
    let (mut txn, ..) = make_transaction_tuple_1();
    unrelated_async_work("bad").await;
    good_outer_db_wrapper(&mut txn).await;
    txn.commit().await.unwrap();

    let (_, mut txn, _) = make_transaction_tuple_2();
    unrelated_async_work("bad").await;
    good_outer_db_wrapper(&mut txn).await;
    txn.commit().await.unwrap();

    let (.., mut txn) = make_transaction_tuple_3();
    unrelated_async_work("bad").await;
    good_outer_db_wrapper(&mut txn).await;
    txn.commit().await.unwrap();
}

// No warnings: non_async_work() is not async
async fn good_no_await() {
    let mut txn = make_transaction();
    non_async_work();
    db::actually_use_txn(txn.deref_mut()).await;
    good_outer_db_wrapper(&mut txn).await;
    txn.commit().await.unwrap();
}

// No warnings: txn.commit() discards the transaction
async fn good_commit() {
    let mut txn = make_transaction();
    db::actually_use_txn(txn.deref_mut()).await;
    txn.commit().await.unwrap();
    unrelated_async_work("good").await;
}

// Warnings: unrelated_async_work does not accept a txn
async fn bad_await() {
    let mut txn = make_transaction();
    unrelated_async_work("bad").await;
    db::actually_use_txn(txn.deref_mut()).await;
    txn.commit().await.unwrap();
}

// No warnings: This is passing the &mut txn to the call triggering the await
async fn bad_call_bad_db_wrapper() {
    let mut txn = make_transaction();
    bad_db_wrapper(&mut txn).await;
    txn.commit().await.unwrap();
}

// No warnings: txn is dropped before we do unrelated async work
async fn good_drop_before_await() {
    {
        let mut txn = make_transaction();
        db::actually_use_txn(txn.deref_mut()).await;
        txn.commit().await.unwrap();
    }
    unrelated_async_work("good").await;
}

// Warnings: Takes transaction by value and uses it across an await point
async fn bad_txn_by_value(mut txn: PgTransaction<'_>) {
    db::actually_use_txn(txn.deref_mut()).await;
    unrelated_async_work("bad").await;
    txn.commit().await.unwrap();
}

// No warnings: Takes transaction by value but commits before doing unrelated work
async fn good_txn_by_value(mut txn: PgTransaction<'_>) {
    db::actually_use_txn(txn.deref_mut()).await;
    txn.commit().await.unwrap();
    unrelated_async_work("good").await;
}

async fn do_txn_by_value() {
    good_txn_by_value(make_transaction()).await;
    bad_txn_by_value(make_transaction()).await;
}

// No warnings: txn is forwarded to the inner wrapper
async fn good_outer_db_wrapper(txn: &mut PgTransaction<'_>) {
    good_inner_db_wrapper(txn).await
}

// No warnings: txn is passed to db::actually_use_txn
async fn good_inner_db_wrapper(txn: &mut PgTransaction<'_>) {
    db::actually_use_txn(txn.deref_mut()).await;
}

// No warnings: txn is passed to each function we're awaiting
async fn call_methods() {
    let mut txn = make_transaction();
    call_good_methods(&mut txn).await;
    call_bad_methods(&mut txn).await;
    txn.commit().await.unwrap();
}

// No warnings: txn is passed to db.good_fn
async fn call_good_methods(txn: &mut PgTransaction<'_>) {
    let db = HasDbMethods;
    db.good_fn(txn).await;

    // txn can also be the receiver
    txn.prepare("SELECT 1").await.unwrap();
}

async fn good_txn_as_receiver() {
    let mut txn = make_transaction();
    txn.prepare("SELECT 1").await.unwrap();
    txn.commit().await.unwrap();
}

// No warnings: txn is passed to db.bad_fun
async fn call_bad_methods(txn: &mut PgTransaction<'_>) {
    let db = HasDbMethods;
    db.bad_fn(txn).await;
}

// Warnings: async work is done while txn is in scope, even though it's not owned by this fn
async fn bad_db_wrapper(txn: &mut PgTransaction<'_>) {
    unrelated_async_work("bad").await;
    db::actually_use_txn(txn.deref_mut()).await;
    unrelated_async_work("bad").await;
}

async fn unrelated_async_work(desc: &'static str) {
    eprintln!("{desc}");
}

fn non_async_work() {}

mod db {
    use sqlx::PgExecutor;

    pub async fn actually_use_txn(_db: impl sqlx::PgExecutor<'_>) {}
    pub async fn use_db_as_trait<DB>(_db: &mut DB)
    where
        for<'db> &'db mut DB: PgExecutor<'db>,
    {
    }
}

struct HasDbMethods;

impl HasDbMethods {
    // No warnings: txn is forwarded to db::actually_use_txn
    pub async fn good_fn(&self, txn: &mut PgTransaction<'_>) {
        non_async_work();
        db::actually_use_txn(txn.deref_mut()).await;
        db::use_db_as_trait(&mut **txn).await;
    }

    // Warnings: unrelated_async_work is called while txn is in scope
    pub async fn bad_fn(&self, _txn: &mut PgTransaction<'_>) {
        unrelated_async_work("bad").await;
    }
}

fn make_transaction() -> sqlx::Transaction<'static, sqlx::Postgres> {
    // We don't actually run this code, so it's ok this is just a todo
    todo!()
}

fn make_transaction_tuple_1() -> (sqlx::Transaction<'static, sqlx::Postgres>, u8, u8) {
    // We don't actually run this code, so it's ok this is just a todo
    todo!()
}

fn make_transaction_tuple_2() -> (u8, sqlx::Transaction<'static, sqlx::Postgres>, u8) {
    // We don't actually run this code, so it's ok this is just a todo
    todo!()
}

fn make_transaction_tuple_3() -> (u8, u8, sqlx::Transaction<'static, sqlx::Postgres>) {
    // We don't actually run this code, so it's ok this is just a todo
    todo!()
}

fn make_pgconn() -> sqlx::PgConnection {
    todo!()
}

fn make_pgpoolconn() -> PoolConnection<Postgres> {
    todo!()
}

async fn pgconn_calls() {
    let mut conn = make_pgconn();
    bad_pgconn_fn(&mut conn).await;
    good_pgconn_fn(conn).await;

    let mut conn = make_pgpoolconn();
    bad_pgpoolconn_fn(&mut conn).await;
    good_pgpoolconn_fn(conn).await;
}

async fn bad_pgconn_fn(_conn: &mut PgConnection) {
    unrelated_async_work("bad").await
}

async fn good_pgconn_fn(conn: PgConnection) {
    std::mem::drop(conn);
    unrelated_async_work("good").await
}

async fn bad_pgpoolconn_fn(_conn: &mut PoolConnection<Postgres>) {
    unrelated_async_work("bad").await
}

async fn good_pgpoolconn_fn(conn: PoolConnection<Postgres>) {
    std::mem::drop(conn);
    unrelated_async_work("good").await
}

async fn bad_unrelated_work_in_closure_upvars() {
    let txn = make_transaction();
    async move {
        unrelated_async_work("bad").await;
        txn.commit().await.unwrap();
    }
    .await;
}

async fn good_related_work_in_closure_upvars() {
    let mut txn = make_transaction();
    async move {
        db::actually_use_txn(txn.deref_mut()).await;
        txn.commit().await.unwrap();

        unrelated_async_work("good").await;
    }
    .await;
}

async fn bad_unrelated_work_in_closure_locals() {
    async move {
        let txn = make_transaction();
        unrelated_async_work("bad").await;
        txn.commit().await.unwrap();
        let txn = make_transaction();
        txn.commit().await.unwrap();
        unrelated_async_work("good").await; // should not lint here
    }
    .await;
}

async fn good_related_work_in_closure_locals() {
    async move {
        let mut txn = make_transaction();
        db::actually_use_txn(txn.deref_mut()).await;
        txn.commit().await.unwrap();

        unrelated_async_work("good").await;
    }
    .await;
}

async fn bad_missing_commit_local() {
    let _ = "keep local scope varied";
    let txn = make_transaction();
    let _ = &txn;
    non_async_work();
}

fn bad_missing_commit_param(_txn: PgTransaction<'_>) {
    non_async_work();
}

async fn good_move_out() -> PgTransaction<'static> {
    make_transaction()
}

// TDD NOTE: When trait detection works, this should emit the lint.
async fn bad_takes_db_reader() {
    let mut txn = make_transaction();
    bad_takes_db_reader_inner(&mut txn).await;
    txn.commit().await.unwrap();
}

async fn bad_takes_db_reader_inner<DB>(_db: &mut DB)
where
    for<'db> &'db mut DB: db_read::DbReader<'db>,
{
    unrelated_async_work("bad").await;
}

#[tokio::main]
async fn main() {
    // Actually call the functions to dead code warnings. But we're not actually running this code,
    // it's here to test the lint
    good_db_related().await;
    good_db_related_tuples().await;
    good_no_await().await;
    good_commit().await;
    bad_await().await;
    bad_unrelated_tuples().await;
    good_drop_before_await().await;
    bad_call_bad_db_wrapper().await;
    call_methods().await;
    good_txn_as_receiver().await;
    do_txn_by_value().await;
    pgconn_calls().await;
    bad_unrelated_work_in_closure_upvars().await;
    good_related_work_in_closure_upvars().await;
    bad_unrelated_work_in_closure_locals().await;
    good_related_work_in_closure_locals().await;
    bad_missing_commit_local().await;
    bad_missing_commit_param(make_transaction());
    let owned_txn = good_move_out().await;
    owned_txn.commit().await.unwrap();
    bad_takes_db_reader().await;
}

pub mod db_read {
    pub trait DbReader<'c>: sqlx::PgExecutor<'c> {}

    impl<'c> DbReader<'c> for &'c mut sqlx::PgConnection {}
}
