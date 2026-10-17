// RUN: %clang_cc1 -fsyntax-only -Wqemu -Wqemu-coroutine-context \
// RUN:   -Wqemu-error-contract -verify %s
// RUN: %clang_cc1 -fsyntax-only -Wqemu -verify=umbrella %s
// RUN: %clang_cc1 -fsyntax-only -Wqemu-error-path-success -verify=path %s
// RUN: %clang_cc1 -fsyntax-only -Wqemu-result-check -Wqemu-memtx-result \
// RUN:   -verify=result %s
// RUN: %clang_cc1 -fsyntax-only -Wqemu -Wno-qemu-coroutine-context \
// RUN:   -Wno-qemu-error-contract -verify=none %s
// none-no-diagnostics
// umbrella-no-diagnostics

typedef _Bool bool;
typedef struct Error Error;

#define QEMU_ANNOTATE(x) __attribute__((annotate(x)))
#define coroutine_fn QEMU_ANNOTATE("coroutine_fn")
#define coroutine_mixed_fn QEMU_ANNOTATE("coroutine_mixed_fn")
#define no_coroutine_fn QEMU_ANNOTATE("no_coroutine_fn")
#define returns_true_on_success QEMU_ANNOTATE("qemu::returns_true_on_success")
#define returns_nonnegative_on_success \
  QEMU_ANNOTATE("qemu::returns_nonnegative_on_success")
#define result_must_be_checked \
  QEMU_ANNOTATE("qemu::result_must_be_checked")
#define output_on_success QEMU_ANNOTATE("qemu::output_on_success")

void coroutine_fn co_only(void); // expected-note 2 {{'co_only' is annotated coroutine-only here}}
void coroutine_mixed_fn co_mixed(void);
void no_coroutine_fn blocking(void); // expected-note {{'blocking' is annotated no-coroutine here}}
void coroutine_mixed_fn no_coroutine_fn context_dispatch(void);

void ordinary_bad(void)
{
  co_only(); // expected-warning {{ordinary function 'ordinary_bad' directly calls coroutine-only function 'co_only'}}
}

void no_coroutine_fn explicit_noncoroutine_bad(void)
{
  co_only(); // expected-warning {{no-coroutine function 'explicit_noncoroutine_bad' directly calls coroutine-only function 'co_only'}}
}

void coroutine_mixed_fn mixed_good(void)
{
  co_only();
}

void coroutine_fn coroutine_bad(void)
{
  blocking(); // expected-warning {{coroutine function 'coroutine_bad' directly calls no-coroutine function 'blocking'}}
  context_dispatch();
}

void coroutine_fn coroutine_good(void)
{
  co_only();
  co_mixed();
}

void ordinary_good(void)
{
  blocking();
  co_mixed();
  context_dispatch();
}

typedef void (*unannotated_callback)(void);

/* Indirect-call context contracts are intentionally not inferred yet. */
void indirect_call_unmodeled(unannotated_callback callback)
{
  callback();
}

void coroutine_address_taken_is_not_a_call(void)
{
  unannotated_callback callback = co_only;
  callback();
}

typedef struct ErrorPropagator {
  Error *local_err;
  Error **errp;
} ErrorPropagator;

#define ERRP_GUARD() \
  ErrorPropagator _auto_errp_prop = { 0, errp }

void error_prepend(Error **errp, const char *fmt, ...);
void error_vprepend(Error **errp, const char *fmt, void *ap);
void error_append_hint(Error **errp, const char *fmt, ...);
void error_setg_internal(Error **errp, const char *file, int line,
                         const char *func, const char *fmt, ...);
void error_free(Error *err);
void error_free_or_abort(Error **errp);
void error_report_err(Error *err);
void error_propagate(Error **dst_errp, Error *local_err);
const char *error_get_pretty(Error *err);
void make_error(Error **errp);

void bad_dereference(Error **errp) // expected-note {{parameter of type 'Error **' declared here}}
{
  if (*errp) { // expected-warning {{parameter 'errp' of type 'Error **' is dereferenced without ERRP_GUARD()}}
  }
}

void bad_helper(Error **errp) // expected-note {{parameter of type 'Error **' declared here}}
{
  error_prepend(errp, "context"); // expected-warning {{error_prepend requires ERRP_GUARD() before passing parameter 'errp' of type 'Error **'}}
}

void guarded_uses(Error **errp)
{
  ERRP_GUARD();
  if (*errp) {
    error_append_hint(errp, "hint");
  }
}

bool returns_true_on_success bad_success_bool(Error **errp)
{
  error_setg_internal(errp, __FILE__, __LINE__, __func__, "failed"); // path-note {{error was set here}}
  return 1; // path-warning {{this return reports success after setting an error through parameter 'errp'}}
}

int returns_nonnegative_on_success bad_success_int(Error **errp, bool fail)
{
  if (fail) {
    error_setg_internal(errp, __FILE__, __LINE__, __func__, "failed"); // path-note {{error was set here}}
    return 0; // path-warning {{this return reports success after setting an error through parameter 'errp'}}
  }
  return -1;
}

bool returns_true_on_success proper_failure(Error **errp)
{
  error_setg_internal(errp, __FILE__, __LINE__, __func__, "failed");
  return 0;
}

int returns_nonnegative_on_success cleared_before_success(Error **errp)
{
  ERRP_GUARD();
  error_setg_internal(errp, __FILE__, __LINE__, __func__, "handled");
  *errp = (Error *)0;
  return 0;
}

/* No return convention is inferred merely from the C return type. */
bool unmodeled_return_contract(Error **errp)
{
  error_setg_internal(errp, __FILE__, __LINE__, __func__, "failed");
  return 1;
}

void consumed_then_used(Error *err)
{
  error_report_err(err); // expected-note {{error object was consumed by 'error_report_err' here}}
  (void)error_get_pretty(err); // expected-warning {{use of Error pointer 'err' after it was consumed}}
}

void consumed_twice(Error *err)
{
  error_free(err); // expected-note {{error object was consumed by 'error_free' here}}
  error_free(err); // expected-warning {{use of Error pointer 'err' after it was consumed}}
}

void propagated_then_used(Error **errp, Error *local_err)
{
  error_propagate(errp, local_err); // expected-note {{error object was consumed by 'error_propagate' here}}
  (void)error_get_pretty(local_err); // expected-warning {{use of Error pointer 'local_err' after it was consumed}}
}

void maybe_propagated_then_reused(Error **errp, Error *local_err, bool failed)
{
  if (failed) {
    error_propagate(errp, local_err); // expected-note {{error object was consumed by 'error_propagate' here}}
  }
  make_error(&local_err); // expected-warning {{possible use of Error pointer 'local_err' after it was consumed}}
}

void reset_after_consuming(Error *err)
{
  error_free(err);
  err = (Error *)0;
  make_error(&err);
  (void)error_get_pretty(err);
}

void clearing_consumer(Error *err)
{
  error_free_or_abort(&err);
  make_error(&err);
}

void cleanup_loop_does_not_leak_consumed_state(Error *err)
{
  bool once = 1;
  while (once) {
    (void)error_get_pretty(err);
    error_free(err);
    once = 0;
  }
}

void same_iteration_loop_bug(Error *err)
{
  bool once = 1;
  while (once) {
    error_free(err); // expected-note {{error object was consumed by 'error_free' here}}
    (void)error_get_pretty(err); // expected-warning {{use of Error pointer 'err' after it was consumed}}
    once = 0;
  }
}

typedef unsigned int MemTxResult;

MemTxResult address_space_read(void);
int result_must_be_checked parse_config(void);
int parse_value(const char *text, int *value output_on_success);
int qemu_strtoi(const char *text, const char **end, int base, int *value);

#define DISCARD_MEMTX_RESULT() address_space_read()

void discarded_results(bool choose)
{
  address_space_read(); // result-warning {{result of memory transaction from 'address_space_read' is discarded; check it or explicitly cast the call to void}}
  parse_config(); // result-warning {{result of 'parse_config' is discarded despite its QEMU must-check contract; check the result or explicitly cast the call to void}}
  parse_value("1", (int *)0); // result-warning {{result of 'parse_value' is discarded despite its QEMU must-check contract; check the result or explicitly cast the call to void}}
  qemu_strtoi("1", (const char **)0, 10, (int *)0); // result-warning {{result of 'qemu_strtoi' is discarded despite its QEMU must-check contract; check the result or explicitly cast the call to void}}
  if (choose)
    address_space_read(); // result-warning {{result of memory transaction from 'address_space_read' is discarded; check it or explicitly cast the call to void}}
  choose ? address_space_read() : address_space_read(); // result-warning 2 {{result of memory transaction from 'address_space_read' is discarded; check it or explicitly cast the call to void}}
  (address_space_read(), 0); // result-warning {{result of memory transaction from 'address_space_read' is discarded; check it or explicitly cast the call to void}}
  DISCARD_MEMTX_RESULT(); // result-warning {{result of memory transaction from 'address_space_read' is discarded; check it or explicitly cast the call to void}}
}

int checked_results(bool choose)
{
  MemTxResult tx = address_space_read();
  int parsed = parse_config();
  if (parse_value("1", &parsed)) {
    return -1;
  }
  (void)address_space_read();
  (void)parse_config();
  return choose ? tx : parsed;
}

typedef MemTxResult (*MemTxCallback)(void);

/* Indirect-call result contracts are intentionally not inferred yet. */
void indirect_result_contract_unmodeled(MemTxCallback callback)
{
  callback();
}
