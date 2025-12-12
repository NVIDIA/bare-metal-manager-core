use rustc_ast::UnOp;
use rustc_data_structures::fx::FxHashMap;
use rustc_hir as hir;
use rustc_hir::def::Res;
use rustc_hir::intravisit::{self, Visitor};
use rustc_hir::{
    Body, Expr, ExprKind, HirId, ImplItem, ImplItemKind, Item, ItemKind, LetStmt, Node, Param,
    PatKind, Path, PathSegment, QPath, YieldSource,
};
use rustc_lint_defs::{Lint, LintPass, LintVec};
use rustc_middle::hir::nested_filter;
use rustc_middle::mir::Location;
use rustc_middle::ty::{Adt, Ty as MiddleTy, TyCtxt, TypeckResults};
use rustc_middle::{bug, mir};
use rustc_mir_dataflow::Analysis;
use rustc_mir_dataflow::impls::{MaybeInitializedPlaces, MaybeUninitializedPlaces};
use rustc_mir_dataflow::move_paths::MoveData;
use rustc_span::def_id::{DefId, LocalDefId};
use rustc_span::{Span, Symbol};
use rustc_type_ir::inherent::SliceLike;

///  ### What it does
///
///  Finds cases where a `sqlx::Transaction` is held while awaiting non-database work.
///
///  ### Why is this bad?
///
///  Transactions should be used to group database writes and reads together, but should not be
///  held open while doing other work. Open transactions consume resources on the PostgreSQL server
/// and cause increased memory usage, as well as the possibility of locking database rows,
/// preventing other queries from running.
///
///  ### Notes
///
///  Database work and non-database work are determined by whether a reference to the transaction
///  is actually passed to the function being awaited. It's considered "unrelated" work if the
///  async function you're calling doesn't accept your transaction as a parameter.
///
///  ### Example
///
///  ```
///  use sqlx::PgPool;
///
///  async fn get_items(pool: PgPool) -> sqlx::Result<()> {
///      let mut txn = pool.begin()
///      db::fetch_items(&mut txn).await?; // GOOD: the txn can be held while awaiting database work
///      do_http_request().await; // BAD: txn is held open while unrelated work is happening
///  }
///
///  async fn do_http_request() {
///  }
///
///  mod db {
///      use sqlx::PgTransaction;
///
///      pub async fn fetch_items(txn: &mut PgTransaction) -> sqlx::Result<()> {
///          // ...
///          Ok(())
///      }
///  }
///  ```
///
///  Instead, finish the transaction before doing unrelated work:
///
///  ```rust
///  use sqlx::PgPool;
///
///  async fn get_items(pool: PgPool) -> sqlx::Result<()> {
///      {
///          let mut txn = pool.begin()
///          db::fetch_items(&mut txn).await?; // GOOD: the txn can be held while awaiting database work
///      }
///      do_http_request().await; // GOOD: txn is dropped before doing the http request
///  }
///
///  async fn do_http_request() {
///  }
///
///  mod db {
///      use sqlx::PgTransaction;
///
///      pub async fn fetch_items(txn: &mut PgTransaction) -> sqlx::Result<()> {
///          // ...
///          Ok(())
///      }
///  }
///  ```
pub static TXN_HELD_ACROSS_AWAIT: &Lint = &Lint {
    name: "txn_held_across_await",
    default_level: ::rustc_lint_defs::Warn,
    desc: "Do not do expensive non-database work while holding open a database transaction",
    is_externally_loaded: false,
    ..Lint::default_fields_for_macro()
};

#[derive(Clone)]
pub struct TxnHeldAcrossAwait {
    txn_symbol_paths: Vec<Vec<Symbol>>,
    txn_self_methods: Vec<Symbol>,
}

impl Default for TxnHeldAcrossAwait {
    fn default() -> Self {
        let txn_symbol_paths = vec![
            "sqlx_core::transaction::Transaction".to_string(),
            "sqlx_postgres::PgTransaction".to_string(),
            "db::Transaction".to_string(),
            "sqlx_postgres::connection::PgConnection".to_string(),
            "sqlx_core::pool::connection::PoolConnection".to_string(),
        ]
        .into_iter()
        .map(|txn| {
            txn.split("::")
                .filter_map(|s| {
                    if s.is_empty() {
                        None
                    } else {
                        Some(Symbol::intern(s))
                    }
                })
                .collect::<Vec<_>>()
        })
        .collect();
        let txn_self_methods = vec!["deref_mut".to_string(), "as_pgconn".to_string()]
            .into_iter()
            .map(|s| Symbol::intern(&s))
            .collect();

        Self {
            txn_symbol_paths,
            txn_self_methods,
        }
    }
}

impl LintPass for TxnHeldAcrossAwait {
    fn name(&self) -> &'static str {
        "TxnHeldAcrossAwait"
    }
    fn get_lints(&self) -> LintVec {
        [TXN_HELD_ACROSS_AWAIT].to_vec()
    }
}

impl TxnHeldAcrossAwait {
    pub fn check_coroutine<'a, 'tcx>(
        &mut self,
        tcx: TyCtxt<'tcx>,
        def_id: LocalDefId,
        mir_body: &'a mir::Body<'tcx>,
    ) {
        // In async rust, functions are turned into a coroutine closure, capturing what is
        // essentially an enum, with variants corresponding to each chunk of code between await
        // points. These are what we're checking.
        if let Some(coroutine_layout) = tcx.mir_coroutine_witnesses(def_id) {
            self.check_interior_types(tcx, def_id, coroutine_layout, mir_body);
        }
    }

    /// Check if the given DefId resolves to a sqlx::Transaction
    fn is_sqlx_transaction(&self, tcx: TyCtxt<'_>, def_id: DefId) -> bool {
        let path = tcx.def_path(def_id);
        let path_as_syms = path
            .data
            .iter()
            .map(|i| i.as_sym(false))
            .collect::<Vec<_>>();
        let result = self
            .txn_symbol_paths
            .iter()
            // TODO: ignoring crates via skip(1), we shouldn't do that
            .any(|txn_path| txn_path.iter().skip(1).eq(path_as_syms.iter()));

        result
    }

    /// Check if the given rustc_middle::Ty (ie. output from typeck) resolves to a sqlx::Transaction
    fn is_sqlx_transaction_ty(&self, tcx: TyCtxt<'_>, ty: &MiddleTy) -> bool {
        let def_id = match ty.peel_refs().kind() {
            Adt(adt, _) => adt.did(),
            _ => {
                return false;
            }
        };
        self.is_sqlx_transaction(tcx, def_id)
    }

    // Check a given coroutine (the implementation of a function with await statements) for any fields
    // carried between await statements (expressed as variants of the coroutine layout) that are
    // `sqlx::Transaction` types, and for which the await statement is not coming from a function in
    // `db::*`. If so, emit a lint warning.
    fn check_interior_types<'a, 'tcx>(
        &self,
        tcx: TyCtxt<'tcx>,
        owner_def_id: LocalDefId,
        coroutine: &mir::CoroutineLayout<'tcx>,
        mir_body: &'a mir::Body<'tcx>,
    ) {
        // Get the user-visible function that desugared into this coroutine
        let outer_fn = tcx.parent_hir_node(tcx.local_def_id_to_hir_id(owner_def_id));

        // Get any txns passed as input parameters (which are sometimes not included in coroutine
        // variants)
        let borrowed_txn_input_params = self.find_txn_input_params(tcx, outer_fn);

        // Get the HIR (high-level representation) body for this coroutine's owner (the function
        // itself)
        let hir_node = tcx.hir_node_by_def_id(owner_def_id);
        let hir_body_id = hir_node.body_id().expect("no HIR body");
        let hir_body = tcx.hir_body(hir_body_id);

        // Gather typeck results, needed to get type info for locals
        let typeck_results = tcx.typeck_body(hir_body_id);

        // Gather all move data in the MIR body (to analyze when txn's are moved out of scope)
        let move_data = MoveData::gather_moves(&mir_body, tcx, |_| true);

        // Now we go through each variant of the coroutine (which correspond to await points), and
        // find any transactions being held across them.
        for (variant, source_info) in coroutine.variant_source_info.iter_enumerated() {
            if source_info.span.is_empty() {
                continue;
            }

            // Are any Transactions being held across this await?
            let mut txn_local_spans: Vec<Span> = Vec::new();

            // First check the fields in this coroutine variant:
            for field in &coroutine.variant_fields[variant] {
                let ty_cause = &coroutine.field_tys[field.clone()];
                if self.is_sqlx_transaction_ty(tcx, &ty_cause.ty) {
                    txn_local_spans.push(ty_cause.source_info.span)
                }
            }

            // Next find any txn locals we're borrowing as part of the function's parameters. These
            // are sometimes not used in a variant, leading to a false negative, because we are
            // still "logically" holding a transaction if we're borrowing it, even if the coroutine
            // variant no longer needs the local.
            for param in &borrowed_txn_input_params {
                // Skip params that already being warned about, to avoid duplicate warnings.
                if !txn_local_spans
                    .iter()
                    .any(|variant_span| variant_span.overlaps(param.pat.span))
                {
                    txn_local_spans.push(param.pat.span)
                }
            }

            // Now we have spans for each txn local in scope across this await point
            for local_span in txn_local_spans {
                // Find the MIR (mid-level representation) local for this span
                let Some((local, local_decl)) = self.find_mir_local(mir_body, local_span) else {
                    bug!("could not find mir local corresponding to local span");
                };

                // Don't warn if the local is not alive (ie. has been moved via a .commit() or
                // something)
                if is_local_dead_at_span(local, source_info.span, &move_data, mir_body, tcx) {
                    continue;
                }

                // If this await is from a function call where we're passing this transaction local,
                // don't warn.
                //
                // Note: We pass the local_decl.source_info.span we got from the MIR local, and not
                // the local_span we got from coroutine.variant_source_info, because the MIR local
                // is the "real" definition of the variable, and the span it returns is the one that
                // will actually match the HIR ID we're looking for. See comments in
                // [`TxnHeldAcrossAwait::find_mir_local`] for more info.
                if DbAwaitFinder::await_is_passing_local_as_param(DbAwaitSearch {
                    await_span: source_info.span,
                    txn_local_span: local_decl.source_info.span,
                    lint: self,
                    tcx,
                    body: tcx.hir_body(outer_fn.body_id().unwrap()),
                    typeck_results,
                }) {
                    continue;
                }

                tcx.node_span_lint(
                    TXN_HELD_ACROSS_AWAIT,
                    hir_body.id().hir_id,
                    source_info.span,
                    |diag| {
                        diag.primary_message(
                            "A sqlx::Transaction is being held across this 'await' point",
                        );
                        diag.span_note(local_span, "Transaction declared here");
                    },
                );
            }
        }
    }

    /// Given a function Node, get any input parameters of type sqlx::Transaction
    fn find_txn_input_params<'tcx>(&self, tcx: TyCtxt<'tcx>, fn_node: Node) -> Vec<Param<'tcx>> {
        if let Node::Item(Item {
            kind:
                ItemKind::Fn {
                    sig,
                    body: fn_body_id,
                    ..
                },
            ..
        })
        | Node::ImplItem(ImplItem {
            kind: ImplItemKind::Fn(sig, fn_body_id),
            ..
        }) = fn_node
        {
            let body = tcx.hir_body(*fn_body_id);
            sig.decl
                .inputs
                .iter()
                .enumerate()
                .filter_map(|(param_index, ty)| {
                    if let rustc_hir::TyKind::Ref(
                        _,
                        rustc_hir::MutTy {
                            ty:
                                rustc_hir::Ty {
                                    kind: rustc_hir::TyKind::Path(qpath),
                                    ..
                                },
                            ..
                        },
                    ) = &ty.kind
                    {
                        let hir::QPath::Resolved(_, path) = qpath else {
                            return None;
                        };
                        let def_id = path.res.opt_def_id()?;
                        if self.is_sqlx_transaction(tcx, def_id.into()) {
                            Some(body.params[param_index])
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                })
                .collect()
        } else {
            vec![]
        }
    }

    /// Check if the expression contained in `txn_local_span` is being passed as an argument to the expression `awaited`.
    ///
    /// In the snippet:
    ///
    /// ```ignore
    /// async fn db_wrapper(txn: &mut sqlx::Transaction) {
    ///     sqlx::query("SELECT true").execute(txn).await.unwrap()
    /// }
    /// ```
    ///
    /// - `txn_local_span` would cover `txn` in db_wrapper's parameter list, since that's where the
    ///   local is defined.
    /// - `awaited` would cover `execute(txn)`, since it's the expression that's actually triggering an
    ///   await.
    ///
    /// In this example, we would return true, since the `txn` binding is being passed as an argument to
    /// `execute`.
    ///
    /// Additionally, these would all qualify as passing txn:
    ///
    /// - `txn.prepare("SELECT true") // txn is the receiver`
    /// - `some_fn(&mut txn) // any level of borrows are ok`
    /// - `some_fn(txn.deref_mut()) // deref_mut() is a special case`
    fn is_passing_txn<'tcx>(
        &self,
        txn_local_hir_id: HirId,
        awaited: &Expr<'tcx>,
        tcx: TyCtxt<'tcx>,
        typeck_results: &TypeckResults,
    ) -> bool {
        let args = match awaited.peel_borrows().kind {
            // e.g. `db::machine::get(db)`
            ExprKind::Call(_, args) => args,
            // e.g. `some_future.await` where the future came from a method call
            ExprKind::MethodCall(_, recv, args, _) => {
                // Short-circuit: Is the transaction the receiver? txn.commit().await,
                // txn.prepare(...).await(), etc count as passing txn (as the self param)
                if let ExprKind::Path(qpath) = recv.kind {
                    if let Some(Res::Local(hir_id)) = qpath_res(&qpath)
                        && hir_id == txn_local_hir_id
                    {
                        return true;
                    }
                }
                if let Some(ty) = typeck_results.expr_ty_opt(recv)
                    && self.is_sqlx_transaction_ty(tcx, &ty)
                {
                    return true;
                }
                args
            }
            _ => return false,
        };

        args.iter().any(|arg| {
            // Is the arg either the txn, or txn.deref_mut()? Either of these count as "doing database work".
            let txn_param_res = match arg.peel_borrows().peel_derefs().kind {
                // The arg is a simple resolved path, optionally with a deref (*) before it.
                ExprKind::Path(QPath::Resolved(_, Path { res, .. })) => Some(res),
                // The arg is an inline method call (ie. `txn.foo()` in `some_func(txn.foo()))`)
                ExprKind::MethodCall(
                    PathSegment {
                        ident: method_ident,
                        ..
                    },
                    receiver,
                    ..,
                ) => {
                    // We only bother checking for simple "txn.foo()", nothing like
                    // "opt_txn.map(|t| t.foo())" or anything complicated.
                    if let ExprKind::Path(QPath::Resolved(
                        _,
                        Path {
                            segments: [PathSegment { res, .. }],
                            ..
                        },
                    )) = receiver.kind
                    {
                        // We only support calling "deref_mut" on the txn to qualify as "doing db work"
                        if self.txn_self_methods.contains(&method_ident.name) {
                            Some(res)
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                }
                _ => None,
            };

            txn_param_res.is_some_and(|res| {
                if let Res::Local(hir_id) = res {
                    hir_id.local_id == txn_local_hir_id.local_id
                } else {
                    false
                }
            })
        })
    }

    fn find_mir_local<'a, 'tcx>(
        &self,
        mir_body: &'a mir::Body<'tcx>,
        txn_local_span: Span,
    ) -> Option<(mir::Local, &'a mir::LocalDecl<'tcx>)> {
        for (local, decl) in mir_body.local_decls.iter_enumerated() {
            // NOTE: We need to use source_equal here (and other places in this file) because we're
            // comparing HIR vs MIR representations of the code, and spans there don't always
            // compare equal, even if they're the same source location.
            if txn_local_span.source_equal(decl.source_info.span) {
                return Some((local, decl));
            }
        }
        None
    }
}

trait ExprExt {
    fn peel_derefs(&self) -> &Self;
}

impl ExprExt for Expr<'_> {
    fn peel_derefs(&self) -> &Self {
        let mut expr = self;
        while let ExprKind::Unary(UnOp::Deref, inner) = &expr.kind {
            expr = inner;
        }
        expr
    }
}

/// Visitor to find two things:
///
/// - The expression that `await_span` (the `.await` statement itself) is chained to, for example
///   `foo()` in `foo().await`
/// - The `HirId` of the local variable that `txn_local_span` refers to.
///
/// With both of these pieces of information, we can answer the question "is this await statement
/// passing this transaction as an argument?" which is how we "allow" a transaction to be held
/// across an await.
struct DbAwaitFinder<'a, 'tcx> {
    tcx: TyCtxt<'tcx>,
    // The span containing the `await` statement itself
    await_span: Span,
    // The span for the original definition of the local variable holding the transaction (typically named `txn`, etc.) We get this from the data in mir_coroutine_witnesses
    txn_local_span: Span,
    // Keep track of all expressions so we can recover the one we're awaiting
    all_exprs: FxHashMap<HirId, &'a Expr<'tcx>>,

    // What we're trying to find:
    txn_local_hir_id: Option<HirId>,
    await_expr: Option<&'a Expr<'tcx>>,
}

impl<'a, 'tcx> Visitor<'tcx> for DbAwaitFinder<'a, 'tcx> {
    type NestedFilter = nested_filter::OnlyBodies;

    fn maybe_tcx(&mut self) -> Self::MaybeTyCtxt {
        self.tcx
    }

    // visit_local is here to find the hir_id of the local indicated by self.txn_local_span, and
    // assign it to self.txn_local_hir_id. This way we can correlate the locals sent to the awaited
    // call, to the txn local being held across the await.
    fn visit_local(&mut self, let_stmt: &'tcx LetStmt<'tcx>) {
        if let PatKind::Tuple(tuple_vars, _dotdot_position) = let_stmt.pat.kind {
            // Statement is a tuple... e.g. `let (txn, stuff) = make_transaction_and_stuff()`;
            for v in tuple_vars.iter() {
                if v.span.source_equal(self.txn_local_span) {
                    self.txn_local_hir_id = Some(v.hir_id);
                }
            }
        } else if let_stmt.pat.span.source_equal(self.txn_local_span) {
            // Statement's `pat` (the place to the left of the equals sign) equals the span we're
            // looking for.
            self.txn_local_hir_id = Some(let_stmt.pat.hir_id);
        }

        intravisit::walk_local(self, let_stmt);
    }

    // visit_expr finds the actual function call that is being `.await`ed, and stores it as self.await_expr.
    fn visit_expr(&mut self, expr: &'tcx Expr<'tcx>) {
        // Keep track of all expressions in this body: We end up visiting the await statement itself
        // after the expression it's awaiting
        self.all_exprs.insert(expr.hir_id, expr);

        // We care about the actual `.await` statements...
        if let ExprKind::Yield(
            _,
            YieldSource::Await {
                expr: Some(awaited),
            },
        ) = expr.kind
        {
            // ... particularly the one that equals `await_span`
            if expr.span.source_equal(self.await_span)
                // ... and for which we've already visited the awaited expression
                && let Some(awaited_expr) = self.all_exprs.get(&awaited)
            {
                self.await_expr = Some(*awaited_expr);
            }
        }

        intravisit::walk_expr(self, expr);
    }
}

/// Helper to add explicit parameter names to DbAwaitFinder::await_is_passing_local_as_param (else
/// two Span arguments can be error-prone.)
struct DbAwaitSearch<'a, 'tcx> {
    // The span containing the `await` statement itself
    await_span: Span,
    // The span for the original definition of the local variable holding the transaction (typically
    // named `txn`, etc.) We get this from the data in mir_coroutine_witnesses
    txn_local_span: Span,
    /// The lint, for calling `.is_passing_txn()`
    lint: &'a TxnHeldAcrossAwait,
    tcx: TyCtxt<'tcx>,
    body: &'a Body<'tcx>,
    typeck_results: &'a TypeckResults<'tcx>,
}

impl<'a, 'tcx> DbAwaitFinder<'a, 'tcx> {
    /// Checks if `await_span` is passing the local originally defined in `local_span` as a parameter.
    ///
    /// For example, in:
    ///
    /// ```ignore
    /// let txn = make_transaction();
    /// do_database_work(txn).await;
    /// ```
    ///
    /// - Parameter `await_span` would match `await` (that is, it's the await statement itself)
    /// - Parameter `local_span` would be `txn` in `let txn = ...` (it's the local we're checking for)
    /// - this would return `true`, since txn is being passed.
    ///
    /// To do this, this function has to:
    ///
    /// - Find the `do_database_work(txn)` awaitee expression (the one being awaited)
    /// - Find the original `let txn = make_transaction()` statement (extracting the hir_id of the
    ///   `txn` variable)
    /// - Once both are found, calls `lint.is_passing_txn()` with the awaitee expression and the txn
    ///   hir_id, and so returns true if any of the args to the expression are locals with the same
    ///   hir_id as the txn local.
    fn await_is_passing_local_as_param(search: DbAwaitSearch<'a, 'tcx>) -> bool {
        let DbAwaitSearch {
            await_span,
            txn_local_span,
            lint,
            tcx,
            body,
            typeck_results,
        } = search;

        let mut finder = Self {
            tcx,
            await_span,
            txn_local_span,
            all_exprs: Default::default(),
            await_expr: None,
            txn_local_hir_id: None,
        };
        finder.visit_body(body);

        // If we've found both the await expr and the txn local, check if it's being passed.
        if let Some(txn_local_hir_id) = finder.txn_local_hir_id
            && let Some(await_expr) = finder.await_expr
        {
            lint.is_passing_txn(txn_local_hir_id, await_expr, tcx, typeck_results)
        } else {
            // Here is a good place to put a debugging eprintln if we need to expand the detection
            // of txn locals: Right now we only find simple `let txn =` or `let (txn, ..) =`
            // statements, and nothing complex like `if let Some(txn) =` or `let SomeStruct { txn,
            // ..} =` yet.
            false
        }
    }
}

/// Check if the given mir::Local is "dead" at the point of a given span, meaning it was moved out
/// of scope, for instance via a call to txn.commit() or txn.rollback().
fn is_local_dead_at_span<'a, 'tcx>(
    local: rustc_middle::mir::Local,
    span: Span,
    move_data: &'a MoveData<'tcx>,
    body: &'a mir::Body<'tcx>,
    tcx: TyCtxt<'tcx>,
) -> bool {
    // Maybe{Un,}InitializedPlaces are analyses performed by the borrow checker which can tell you
    // what "places" (storage holding locals) are maybe-initialized and maybe-initialized at a given
    // source code location. If a local is in maybe-uninitialized and not in maybe-initialized, it's
    // "dead" at that point (ie. it's been moved, usually via a call to txn.rollback() or txn.commit().)
    let mut maybe_initialized_places = MaybeInitializedPlaces::new(tcx, body, move_data)
        .iterate_to_fixpoint(tcx, body, None)
        .into_results_cursor(body);
    let mut maybe_uninitialized_places = MaybeUninitializedPlaces::new(tcx, body, move_data)
        .iterate_to_fixpoint(tcx, body, None)
        .into_results_cursor(body);

    // Iterate through each BasicBlock (chunk of code) and each Statement within, until we get to
    // the span we're looking for (ie. the `.await` call), and return whether the local (txn) we're
    // looking for is alive or dead when we get there.
    let mut is_dead = false;
    'outer: for (block, block_data) in body.basic_blocks.iter_enumerated() {
        for (statement_index, statement) in block_data.statements.iter().enumerate() {
            let loc = Location {
                block,
                statement_index,
            };

            // We got to the span we're looking for, we're done, and we can return `is_dead`.
            if statement.source_info.span.source_equal(span) {
                break 'outer;
            }

            // Check if the local is alive or dead after this statement, and store it as is_dead.
            maybe_uninitialized_places.seek_after_primary_effect(loc);
            maybe_initialized_places.seek_after_primary_effect(loc);
            let uninits = maybe_uninitialized_places.get();
            let inits = maybe_initialized_places.get();
            if let Some(move_path_index) = move_data.rev_lookup.find_local(local) {
                if uninits.contains(move_path_index) && !inits.contains(move_path_index) {
                    is_dead = true;
                } else if inits.contains(move_path_index) && !uninits.contains(move_path_index) {
                    is_dead = false;
                }
            }
        }
    }

    is_dead
}

pub fn qpath_res(qpath: &hir::QPath<'_>) -> Option<Res> {
    match *qpath {
        QPath::Resolved(_, path) => Some(path.res),
        _ => None,
    }
}
