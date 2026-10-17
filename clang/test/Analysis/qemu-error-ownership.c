// RUN: %clang_analyze_cc1 -analyzer-checker=core,alpha.qemu.ErrorOwnership \
// RUN:   -verify %s

typedef struct Error Error;

void error_free(Error *err);
void error_report_err(Error *err);
void error_reportf_err(Error *err, const char *fmt, ...);
void error_propagate(Error **dst, Error *local);
const char *error_get_pretty(const Error *err);
void set_error(Error **errp);
int try_set_error(Error **errp);

#define REPORT_ERROR(err) error_report_err(err)

void double_consume(Error *err) {
  if (!err)
    return;
  error_report_err(err);
  error_free(err);       // expected-warning {{QEMU Error object is consumed more than once}}
}

void use_after_report(Error *err) {
  if (!err)
    return;
  REPORT_ERROR(err);
  error_get_pretty(err);   // expected-warning {{QEMU Error object is used after its ownership was transferred}}
}

void stale_output_destination(Error *err, Error **dst) {
  if (!err)
    return;
  error_propagate(dst, err);
  set_error(&err);           // expected-warning {{QEMU Error output destination still contains a consumed pointer; reset it to null before reuse}}
}

void stale_output_after_producer(Error **dst) {
  Error *err = 0;
  set_error(&err);
  if (!err)
    return;
  error_propagate(dst, err);
  set_error(&err); // expected-warning {{QEMU Error output destination still contains a consumed pointer; reset it to null before reuse}}
}

void stale_output_after_result_check(Error **dst) {
  Error *err = 0;
  int result = try_set_error(&err);
  if (result < 0)
    error_propagate(dst, err);
  set_error(&err); // expected-warning {{QEMU Error output destination still contains a consumed pointer; reset it to null before reuse}}
}

void alias_after_consume(Error *err) {
  Error *alias = err;
  if (!err)
    return;
  error_free(err);
  error_reportf_err(alias, "context: "); // expected-warning {{QEMU Error object is consumed more than once}}
}

void mutually_exclusive_use_is_safe(Error *err, int report) {
  if (!err)
    return;
  if (report)
    error_report_err(err);
  else
    error_get_pretty(err);
}

void reset_before_output_is_safe(Error *err) {
  if (!err)
    return;
  error_free(err);
  err = 0;
  set_error(&err);
}

void null_is_safe(void) {
  Error *err = 0;
  error_free(err);
  set_error(&err);
}

void indirect_consumer_is_conservative(Error *err,
                                       void (*consume)(Error *)) {
  if (!err)
    return;
  consume(err);
  error_get_pretty(err);
}
