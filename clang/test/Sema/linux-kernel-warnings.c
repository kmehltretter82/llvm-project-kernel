// RUN: %clang_cc1 -fsyntax-only -ffreestanding -Wlinux-kernel \
// RUN:   -verify=kernel -verify-ignore-unexpected=note %s
// RUN: %clang_cc1 -fsyntax-only -ffreestanding -Wlinux-kernel-bool-return \
// RUN:   -verify=bool-return %s
// RUN: %clang_cc1 -fsyntax-only -ffreestanding -Wlinux-kernel-usercopy \
// RUN:   -verify=usercopy -verify-ignore-unexpected=note %s
// RUN: %clang_cc1 -fsyntax-only -ffreestanding -Wlinux-kernel-error-pointer \
// RUN:   -verify=error-pointer -verify-ignore-unexpected=note %s
// RUN: %clang_cc1 -fsyntax-only -ffreestanding -Wlinux-kernel-allocator \
// RUN:   -verify=allocator %s
// RUN: %clang_cc1 -fsyntax-only -ffreestanding -Wlinux-kernel-irq \
// RUN:   -verify=irq %s
// RUN: %clang_cc1 -fsyntax-only -ffreestanding -Wlinux-kernel-errno \
// RUN:   -verify=errno %s
// RUN: %clang_cc1 -fsyntax-only -ffreestanding -Wno-everything \
// RUN:   -verify=disabled %s
// RUN: %clang_cc1 -fsyntax-only -ffreestanding -Wlinux-kernel \
// RUN:   -Wno-linux-kernel-bool-return -Wno-linux-kernel-usercopy \
// RUN:   -Wno-linux-kernel-error-pointer -Wno-linux-kernel-allocator \
// RUN:   -Wno-linux-kernel-irq -Wno-conditional-uninitialized \
// RUN:   -verify=overrides %s

// disabled-no-diagnostics
// overrides-no-diagnostics

typedef _Bool bool;

#define EFAULT 14
#define EINVAL 22
#define NULL ((void *)0)

unsigned long copy_from_user(void *, const void *, unsigned long);
unsigned long copy_to_user(void *, const void *, unsigned long);

void *kmalloc(unsigned long, unsigned int);
void *kmalloc_noprof(unsigned long, unsigned int);
void *kmem_cache_alloc_trace(void *, unsigned int, unsigned long);
void *kzalloc(unsigned long, unsigned int);
void *devm_kstrdup(void *, const char *, unsigned int);
void *vmalloc(unsigned long);
void *kvmalloc(unsigned long, unsigned int);
const char *kstrdup_const(const char *, unsigned int);
void kfree(const void *);
void vfree(const void *);
void kvfree(const void *);
void devm_kfree(void *, const void *);
void kfree_const(const void *);
bool IS_ERR(const void *);
bool IS_ERR_OR_NULL(const void *);
long PTR_ERR(const void *);
long PTR_ERR_OR_ZERO(const void *);
void *ERR_PTR(long);

void *filp_open(const char *, int, int);
void *class_create(const char *);
void *kthread_create_on_node(void);
void *__root_device_register(const char *, void *);
void *clk_get_parent(void *);
void mutate_pointer(void **);
int platform_get_irq(void *, unsigned int);

struct stored_results {
  int irq;
  void *allocation;
};

extern int allocation_profiling_enabled;
#define alloc_hooks(do_alloc)                                                  \
  __extension__({                                                             \
    __typeof__(do_alloc) result;                                              \
    if (allocation_profiling_enabled)                                         \
      result = do_alloc;                                                      \
    else                                                                      \
      result = do_alloc;                                                      \
    result;                                                                   \
  })
#define kernel_kmalloc(size, flags) alloc_hooks(kmalloc_noprof(size, flags))
#define root_device_register(name) __root_device_register(name, NULL)
#define optional_error(error) ERR_PTR(error)
#define WARN_ON(condition) __builtin_expect(!!(condition), 0)
#define BUG_ON(condition)                                                        \
  do {                                                                           \
    if (condition)                                                               \
      __builtin_trap();                                                          \
  } while (0)
#define fake_xchg(pointer, value)                                            \
  __extension__({                                                           \
    __typeof__(*(pointer)) old_value = (value);                              \
    __asm__ volatile("" : "+r"(old_value));                                 \
    old_value;                                                              \
  })

bool negative_errno_is_true(void) {
  return -EINVAL; // kernel-warning {{negative value returned from a boolean function evaluates to true}} bool-return-warning {{negative value returned from a boolean function evaluates to true}}
}

bool ordinary_bool_result(int error) {
  return error < 0;
}

int negative_usercopy_test(void *to, const void *from, unsigned long size) {
  int residual = copy_from_user(to, from, size);

  if (residual < 0) // kernel-warning {{copy_from_user returns the number of bytes not copied, never a negative errno}} usercopy-warning {{copy_from_user returns the number of bytes not copied, never a negative errno}}
    return -EFAULT;
  return residual != 0 ? -EFAULT : 0;
}

int reversed_usercopy_test(void *to, const void *from, unsigned long size) {
  int residual;

  residual = copy_to_user(to, from, size);
  if (0 > residual) // kernel-warning {{copy_to_user returns the number of bytes not copied, never a negative errno}} usercopy-warning {{copy_to_user returns the number of bytes not copied, never a negative errno}}
    return -EFAULT;
  return residual ? -EFAULT : 0;
}

int direct_usercopy_test(void *to, const void *from, unsigned long size) {
  if (copy_from_user(to, from, size) < 0) // kernel-warning {{copy_from_user returns the number of bytes not copied, never a negative errno}} usercopy-warning {{copy_from_user returns the number of bytes not copied, never a negative errno}}
    return -EFAULT;
  return 0;
}

int usercopy_compared_with_errno(void *to, const void *from,
                                 unsigned long size) {
  int residual = copy_from_user(to, from, size);

  return residual == -EFAULT; // kernel-warning {{copy_from_user returns the number of bytes not copied, never a negative errno}} usercopy-warning {{copy_from_user returns the number of bytes not copied, never a negative errno}}
}

int usercopy_nonpositive_means_success(void *to, const void *from,
                                       unsigned long size) {
  return copy_from_user(to, from, size) <= 0;
}

int example_ioctl(void *to, const void *from, unsigned long size) {
  return copy_to_user(to, from, size); // kernel-warning {{returning the residual byte count from copy_to_user exposes a positive failure value through a signed return type}} usercopy-warning {{returning the residual byte count from copy_to_user exposes a positive failure value through a signed return type}}
}

unsigned long usercopy_residual_wrapper(void *to, const void *from,
                                        unsigned long size) {
  return copy_to_user(to, from, size);
}

int signed_residual_helper(void *to, const void *from, unsigned long size) {
  return copy_to_user(to, from, size);
}

int nullable_checked_as_errptr(unsigned long size) {
  void *allocation = kmalloc(size, 0);

  if (IS_ERR(allocation)) // kernel-warning {{kmalloc returns NULL on failure, which IS_ERR does not detect}} error-pointer-warning {{kmalloc returns NULL on failure, which IS_ERR does not detect}}
    return -EFAULT;
  if (!allocation)
    return -EFAULT;
  return 0;
}

int nullable_getter_checked_as_errptr(void *clock) {
  void *parent = clk_get_parent(clock);

  if (IS_ERR(parent)) // kernel-warning {{clk_get_parent returns NULL on failure, which IS_ERR does not detect}} error-pointer-warning {{clk_get_parent returns NULL on failure, which IS_ERR does not detect}}
    return PTR_ERR(parent); // kernel-warning {{clk_get_parent returns NULL on failure, which PTR_ERR converts to success}} error-pointer-warning {{clk_get_parent returns NULL on failure, which PTR_ERR converts to success}}
  return 0;
}

long nullable_converted_to_errno(unsigned long size) {
  void *allocation = kzalloc(size, 0);

  return PTR_ERR_OR_ZERO(allocation); // kernel-warning {{kzalloc returns NULL on failure, which PTR_ERR_OR_ZERO converts to success}} error-pointer-warning {{kzalloc returns NULL on failure, which PTR_ERR_OR_ZERO converts to success}}
}

long nullable_passed_to_ptr_err(unsigned long size) {
  return PTR_ERR(kmalloc(size, 0)); // kernel-warning {{kmalloc returns NULL on failure, which PTR_ERR converts to success}} error-pointer-warning {{kmalloc returns NULL on failure, which PTR_ERR converts to success}}
}

int allocation_macro_checked_as_errptr(unsigned long size) {
  void *allocation = kernel_kmalloc(size, 0);

  return IS_ERR(allocation); // kernel-warning {{kmalloc_noprof returns NULL on failure, which IS_ERR does not detect}} error-pointer-warning {{kmalloc_noprof returns NULL on failure, which IS_ERR does not detect}}
}

int old_kmalloc_expansion_checked_as_errptr(void *cache, unsigned long size) {
  void *allocation = kmem_cache_alloc_trace(cache, 0, size);

  return IS_ERR(allocation); // kernel-warning {{kmem_cache_alloc_trace returns NULL on failure, which IS_ERR does not detect}} error-pointer-warning {{kmem_cache_alloc_trace returns NULL on failure, which IS_ERR does not detect}}
}

int generic_allocation_checked_as_errptr(unsigned long size) {
  void *allocation =
      _Generic(size, unsigned long: kmalloc(size, 0),
               default: kzalloc(size, 0));

  return IS_ERR(allocation); // kernel-warning {{kmalloc returns NULL on failure, which IS_ERR does not detect}} error-pointer-warning {{kmalloc returns NULL on failure, which IS_ERR does not detect}}
}

int chosen_allocation_checked_as_errptr(unsigned long size) {
  void *allocation =
      __builtin_choose_expr(1, kzalloc(size, 0), kmalloc(size, 0));

  return IS_ERR(allocation); // kernel-warning {{kzalloc returns NULL on failure, which IS_ERR does not detect}} error-pointer-warning {{kzalloc returns NULL on failure, which IS_ERR does not detect}}
}

int errptr_checked_as_null(const char *path) {
  void *file = filp_open(path, 0, 0);

  if (!file) // kernel-warning {{filp_open returns an encoded error pointer on failure, which a NULL test does not detect}} error-pointer-warning {{filp_open returns an encoded error pointer on failure, which a NULL test does not detect}}
    return -EFAULT;
  if (file == NULL) // kernel-warning {{filp_open returns an encoded error pointer on failure, which a NULL test does not detect}} error-pointer-warning {{filp_open returns an encoded error pointer on failure, which a NULL test does not detect}}
    return -EFAULT;
  return IS_ERR(file) ? -EFAULT : 0;
}

int errptr_null_assertions_are_not_failure_checks(const char *path) {
  void *file = filp_open(path, 0, 0);

  WARN_ON(file == NULL);
  BUG_ON(!file);
  return IS_ERR(file) ? PTR_ERR(file) : 0;
}

int combined_error_pointer_guard(void) {
  void *task = kthread_create_on_node();

  if (task == NULL || IS_ERR(task))
    return -EFAULT;
  task = kthread_create_on_node();
  if (!task || IS_ERR(task))
    return -EFAULT;
  return 0;
}

int standard_combined_error_pointer_guard(void) {
  void *task = kthread_create_on_node();

  return IS_ERR_OR_NULL(task);
}

int positive_errptr_condition_is_not_a_failure_test(void) {
  void *class = class_create("example");

  if (IS_ERR(class))
    return PTR_ERR(class);
  if (class)
    return 0;
  return -EFAULT;
}

int positive_test_after_errptr_guard(void) {
  void *task = kthread_create_on_node();

  if (IS_ERR(task))
    return PTR_ERR(task);
  if (task != NULL)
    return 0;
  return -EFAULT;
}

int errptr_macro_checked_as_null(void) {
  void *device = root_device_register("example");

  return device == NULL; // kernel-warning {{__root_device_register returns an encoded error pointer on failure, which a NULL test does not detect}} error-pointer-warning {{__root_device_register returns an encoded error pointer on failure, which a NULL test does not detect}}
}

int top_level_assignment_checked_as_null(const char *path) {
  void *file;

  file = filp_open(path, 0, 0);
  return !file; // kernel-warning {{filp_open returns an encoded error pointer on failure, which a NULL test does not detect}} error-pointer-warning {{filp_open returns an encoded error pointer on failure, which a NULL test does not detect}}
}

int stored_error_pointer_checked_as_null(struct stored_results *results,
                                         const char *path) {
  results->allocation = filp_open(path, 0, 0);
  return !results->allocation; // kernel-warning {{filp_open returns an encoded error pointer on failure, which a NULL test does not detect}} error-pointer-warning {{filp_open returns an encoded error pointer on failure, which a NULL test does not detect}}
}

int conditional_origin_checked_as_null(const char *path, int condition) {
  void *file = condition ? filp_open(path, 0, 0) : filp_open(path, 0, 0);

  return !file; // kernel-warning {{filp_open returns an encoded error pointer on failure, which a NULL test does not detect}} error-pointer-warning {{filp_open returns an encoded error pointer on failure, which a NULL test does not detect}}
}

int address_escape_forgets_origin(const char *path) {
  void *file = filp_open(path, 0, 0);

  mutate_pointer(&file);
  return !file;
}

int asm_output_forgets_origin(const char *path) {
  void *file = filp_open(path, 0, 0);

  __asm__ volatile("" : "+r"(file));
  return !file;
}

int branch_dependent_origin_is_unknown(void *pointer, int condition) {
  if (condition)
    pointer = filp_open("file", 0, 0);
  else if (!pointer)
    return -EFAULT;
  return 0;
}

int branch_local_origin_is_known(int condition) {
  if (condition) {
    void *file = filp_open("file", 0, 0);

    if (!file) // kernel-warning {{filp_open returns an encoded error pointer on failure, which a NULL test does not detect}} error-pointer-warning {{filp_open returns an encoded error pointer on failure, which a NULL test does not detect}}
      return -EFAULT;
  }
  return 0;
}

int opaque_statement_expression_has_no_origin(void **slot) {
  void *old_value = fake_xchg(slot, ERR_PTR(-EINVAL));

  return !old_value;
}

void *invalid_error_pointer(void) {
  return ERR_PTR(0); // kernel-warning {{call to ERR_PTR() requires a negative errno argument}} error-pointer-warning {{call to ERR_PTR() requires a negative errno argument}}
}

void *positive_error_pointer(void) {
  return ERR_PTR(1); // kernel-warning {{call to ERR_PTR() requires a negative errno argument}} error-pointer-warning {{call to ERR_PTR() requires a negative errno argument}}
}

void *valid_error_pointer(void) {
  return ERR_PTR(-EINVAL);
}

void *macro_expanded_zero_error_is_ignored(void) {
  return optional_error(0);
}

int status_converted_with_err_ptr_may_be_null(int status) {
  void *result = ERR_PTR(status);

  return result == NULL;
}

void allocator_release_mismatches(void *device, unsigned long size) {
  void *managed = devm_kstrdup(device, "value", 0);
  void *virtual = vmalloc(size);
  void *mixed = kvmalloc(size, 0);
  void *slab = kmalloc(size, 0);
  const char *constant = kstrdup_const("value", 0);

  kfree(managed); // kernel-warning {{devm_kstrdup() result must not be released with kfree(); use devm_kfree()}} allocator-warning {{devm_kstrdup() result must not be released with kfree(); use devm_kfree()}}
  kfree(virtual); // kernel-warning {{vmalloc() result must not be released with kfree(); use vfree()}} allocator-warning {{vmalloc() result must not be released with kfree(); use vfree()}}
  vfree(mixed); // kernel-warning {{kvmalloc() result must not be released with vfree(); use kvfree()}} allocator-warning {{kvmalloc() result must not be released with vfree(); use kvfree()}}
  vfree(slab); // kernel-warning {{kmalloc() result must not be released with vfree(); use kfree()}} allocator-warning {{kmalloc() result must not be released with vfree(); use kfree()}}
  kfree(constant); // kernel-warning {{kstrdup_const() result must not be released with kfree(); use kfree_const()}} allocator-warning {{kstrdup_const() result must not be released with kfree(); use kfree_const()}}
}

void stored_allocator_release_mismatch(struct stored_results *results,
                                       void *device) {
  results->allocation = devm_kstrdup(device, "value", 0);
  kfree(results->allocation); // kernel-warning {{devm_kstrdup() result must not be released with kfree(); use devm_kfree()}} allocator-warning {{devm_kstrdup() result must not be released with kfree(); use devm_kfree()}}
}

void correct_allocator_releases(void *device, unsigned long size) {
  void *managed = devm_kstrdup(device, "value", 0);
  void *virtual = vmalloc(size);
  void *mixed = kvmalloc(size, 0);
  void *slab = kmalloc(size, 0);
  const char *constant = kstrdup_const("value", 0);

  devm_kfree(device, managed);
  vfree(virtual);
  kvfree(mixed);
  kfree(slab);
  kfree_const(constant);
}

int irq_boolean_test(void *device) {
  int irq_number = platform_get_irq(device, 0);

  if (!irq_number) // kernel-warning {{platform_get_irq() returns an IRQ number or a negative errno; a boolean test does not detect errors}} irq-warning {{platform_get_irq() returns an IRQ number or a negative errno; a boolean test does not detect errors}}
    return -EINVAL;
  return irq_number;
}

int irq_zero_comparison(void *device) {
  int irq_number = platform_get_irq(device, 0);

  if (irq_number <= 0) // kernel-warning {{platform_get_irq() returns an IRQ number or a negative errno; compare with zero}} irq-warning {{platform_get_irq() returns an IRQ number or a negative errno; compare with zero}}
    return -EINVAL;
  return irq_number;
}

int stored_irq_zero_comparison(struct stored_results *results, void *device) {
  results->irq = platform_get_irq(device, 0);
  if (results->irq == 0) // kernel-warning {{platform_get_irq() returns an IRQ number or a negative errno; compare with zero}} irq-warning {{platform_get_irq() returns an IRQ number or a negative errno; compare with zero}}
    return -EINVAL;
  return results->irq;
}

int correct_irq_check(void *device) {
  int irq_number = platform_get_irq(device, 0);

  if (irq_number < 0)
    return irq_number;
  return 0;
}

int positive_errno_return(void) {
  return EINVAL; // errno-warning {{returning positive errno EINVAL reports success}}
}

int device_status_to_errno(int status) {
  return status ? EINVAL : 0;
}

unsigned long negative_errno_from_unsigned_function(void) {
  return -EFAULT; // errno-warning {{negative errno returned from an unsigned function becomes a large positive value}}
}

int correct_negative_errno_return(void) {
  return -EINVAL;
}

unsigned long explicit_unsigned_sentinel(void) {
  return (unsigned long)-1;
}

int correct_contract_checks(void *to, const void *from, unsigned long size) {
  void *allocation = kmalloc(size, 0);
  void *file = filp_open("file", 0, 0);
  unsigned long residual = copy_from_user(to, from, size);

  if (!allocation)
    return -EFAULT;
  if (IS_ERR(file))
    return PTR_ERR(file);
  return residual ? -EFAULT : 0;
}

int conditional_uninitialized(int disabled, int filter) {
  int error; // kernel-note {{initialize the variable 'error' to silence this warning}}

  if (disabled)
    goto out;
  error = 0;
out:
  if (filter && error) // kernel-warning {{variable 'error' may be uninitialized when used here}}
    return error;
  return 0;
}
