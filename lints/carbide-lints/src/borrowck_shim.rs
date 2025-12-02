use std::sync::{Arc, LazyLock, RwLock};

use rustc_data_structures::fx::FxIndexMap;
use rustc_hir::{
    Closure, ClosureKind, CoroutineDesugaring, CoroutineKind, Expr, ExprKind, ImplItem,
    ImplItemKind, Item, ItemKind, Node,
};
use rustc_middle::ty::{DefinitionSiteHiddenType, TyCtxt};
use rustc_span::ErrorGuaranteed;
use rustc_span::def_id::LocalDefId;

use crate::txn_held_across_await::TxnHeldAcrossAwait;

/// The type for the mir_borrowck query in rustc, which we're overriding.
type BorrowckQueryFn = Box<
    dyn Fn(
            TyCtxt<'_>,
            LocalDefId,
        )
            -> Result<&FxIndexMap<LocalDefId, DefinitionSiteHiddenType<'_>>, ErrorGuaranteed>
        + Send
        + Sync,
>;

/// This is set by CarbideLints::config when starting up, once all default queries are populated.
pub static ORIG_BORROWCK_QUERY: LazyLock<Arc<RwLock<Option<BorrowckQueryFn>>>> =
    LazyLock::new(|| Arc::new(RwLock::new(None)));

pub struct BorrowckShim;

impl BorrowckShim {
    pub fn new() -> Self {
        BorrowckShim {}
    }

    /// Entrypoint to our lint(s) for a given LocalDefId: First call the default mir_borrowck, then
    /// before returning, if LocalDefId refers to an async function, run TxnHeldAcrossAwait on it.
    pub fn mir_borrowck<'tcx>(
        &mut self,
        tcx: TyCtxt<'tcx>,
        def_id: LocalDefId,
    ) -> Result<&'tcx FxIndexMap<LocalDefId, DefinitionSiteHiddenType<'tcx>>, ErrorGuaranteed> {
        let guard = ORIG_BORROWCK_QUERY.read().expect("lock poisoned");
        let result =
            guard
                .as_ref()
                .expect("no mir_borrowck query set, shim not configured")(tcx, def_id);

        let parent_hir_node = tcx.hir_node(tcx.local_def_id_to_hir_id(def_id));

        // If this is a function, get the surrounding HIR (high-level representation) node
        let maybe_body_id = match parent_hir_node {
            Node::Item(Item {
                kind: ItemKind::Fn { body, .. },
                ..
            }) => Some(body),
            Node::ImplItem(ImplItem {
                kind: ImplItemKind::Fn(_, body_id),
                ..
            }) => Some(body_id),
            _ => None,
        };

        if let Some(body_id) = maybe_body_id {
            let hir_body = tcx.hir_node(body_id.hir_id);

            // We care about HIR bodies which are coroutines, which is how async functions are
            // represented (desugared)
            match hir_body {
                Node::Expr(Expr {
                    kind:
                        ExprKind::Closure(Closure {
                            def_id: closure_def_id,
                            // body: closure_body,
                            kind:
                                ClosureKind::Coroutine(CoroutineKind::Desugared(
                                    CoroutineDesugaring::Async,
                                    _,
                                )),
                            ..
                        }),
                    ..
                }) => {
                    // Get the MIR (middle-level representation) body, which holds the borrowck and
                    // typeck results we need, and pass it to TxnHeldAcrossAwait.
                    let mir_promoted = tcx.mir_promoted(closure_def_id).0.borrow();
                    TxnHeldAcrossAwait::default().check_coroutine(
                        tcx,
                        *closure_def_id,
                        &mir_promoted,
                    )
                }

                _ => {}
            };
        }
        result
    }
}
