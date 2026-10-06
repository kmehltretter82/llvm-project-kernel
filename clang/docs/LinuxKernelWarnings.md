# Linux kernel warnings

Clang's `-Wlinux-kernel` option enables diagnostics that use Linux kernel API
contracts and coding conventions. The option is deliberately off by default:
the same function names can have different semantics in other freestanding C
programs.

The umbrella currently enables these groups:

- `-Wlinux-kernel-bool-return` diagnoses a negative integer constant returned
  from a `bool` function. C converts every nonzero integer, including a negative
  errno, to `true`.
- `-Wlinux-kernel-usercopy` diagnoses negative-error tests on the residual byte
  count returned by `copy_from_user()`, `copy_to_user()`, `clear_user()`, and
  their low-level variants. It also diagnoses returning that residual directly
  from common errno-returning kernel entry points, such as ioctl, read, write,
  and sysfs callbacks. Such a return exposes a positive failure value to callers
  expecting zero or a negative errno. These APIs return zero on success and a
  positive byte count on a short copy.
- `-Wlinux-kernel-error-pointer` diagnoses selected mixes of Linux's two common
  pointer failure conventions. It catches `IS_ERR()` or `PTR_ERR*()` applied to
  core allocators that return `NULL`, and NULL tests applied to established
  APIs that return `ERR_PTR()` values. To avoid warning about a positive test
  after an `IS_ERR()` guard, this check is limited to `!pointer` and
  `pointer == NULL`. It also rejects constant nonnegative arguments to
  `ERR_PTR()`.
- `-Wlinux-kernel-allocator` diagnoses direct allocation results released by
  an incompatible helper. The modeled families include slab, vmalloc,
  kvmalloc, device-managed, and constant-string allocations.
- `-Wlinux-kernel-irq` diagnoses boolean tests of the platform IRQ lookup
  helpers. These helpers return a positive IRQ number or a negative errno, so
  a boolean test accepts every error as a valid IRQ.
- `-Wlinux-kernel-errno-truncation` diagnoses a negative errno returned from
  a function whose return type is narrower than `int`. The value is truncated
  and the caller cannot recognize it.
- `-Wlinux-kernel-unsigned-error-check` diagnoses `x < 0` and `x >= 0` when
  the previous statement stored the result of a function returning a signed
  integer in the unsigned `x`. The comparison is constant and a negative error
  code goes undetected. An explicit cast on the stored value states the intent
  and is not diagnosed.
- `-Wlinux-kernel-wrong-check` also diagnoses `PTR_ERR(b)` in the branch
  that `if (IS_ERR(a))` leads to, when `b` is another pointer and the branch
  does not assign it.
- `-Wlinux-kernel-wrong-check` diagnoses a failure test that directly follows
  `x = f();` but tests something else: the object that `x` is a member of,
  which the assignment has already dereferenced, or another value of the same
  type when the test is `IS_ERR()` or `f()` is an allocator that returns
  `NULL`. A batch of assignments followed by their tests
  (`a = f(); b = f(); if (IS_ERR(a))`) is left alone.
- `-Wlinux-kernel-error-path-success` diagnoses `return ret` where `ret` is
  known to be zero on some path and a failure has just been reported. Two
  shapes are recognized: a return that an error-level message dominates, and
  a `goto` to a shared exit label directly after such a message. It also
  diagnoses `dev_err_probe(dev, ret, ...)` with such a `ret`. Error-level
  messages are the kernel's `*_err` printers, `printk()` with `KERN_ERR` or
  a more severe level, and driver logging helpers whose text describes a
  failure. Audit records do not count. Only variables that look like an
  error code are followed: the name is `ret`, `err`, `rc`, `status` or
  similar, the variable is given a non-constant value or a negative
  constant somewhere, and it is not counted up or down. A `goto` to a label
  inside a loop is not an exit. The note points at the message that makes
  the path a failure path.
- `-Wlinux-kernel-cleanup-return` diagnoses `return p;` where `p` was
  declared with `__free()`. The cleanup function releases the pointer while
  the function returns it. `return_ptr(p)` is what was meant.
- `-Wlinux-kernel-counted-by-order` diagnoses a use of a `__counted_by()`
  flexible array before the counter is set, for an object that the function
  has just allocated. The bounds checks of the fortified string functions and
  of the array bounds sanitizer go by the counter, which a fresh object has at
  zero. A use is an element access, or the array handed to a function. The
  counter counts as set after an assignment to it, after a call that is
  passed the object, and when the address of another member is taken. The
  allocation macros that store the counter themselves (`kzalloc_flex()` and
  relatives) are recognized. The warning is given only when no path from the
  allocation to the use sets the counter.
- `-Wuninitialized-cleanup` is not specific to the kernel. It diagnoses a
  variable with the `cleanup` attribute whose cleanup function runs while the
  variable is uninitialized on every path to that scope exit:

  ```c
  struct foo *p __free(kfree);

  if (!ready)
          return -EAGAIN;   /* __free_kfree() reads an uninitialized p */
  p = kmalloc(sizeof(*p), GFP_KERNEL);
  ```

  `-Wconditional-uninitialized-cleanup`, outside the umbrella, covers the
  variable that is uninitialized on some of the paths only.
- `-Wconditional-uninitialized` supplies the existing analysis that is
  especially useful for kernel cleanup labels and configuration-driven control
  flow. Uses that are only reachable uninitialized on paths excluded by
  correlated conditions are no longer reported there. They remain available
  under `-Wconditional-uninitialized-correlated`.

`-Wlinux-kernel-missing-error-code` is available separately. It is the
counterpart of `-Wlinux-kernel-error-path-success` for a failure path that
prints nothing:

```c
ret = setup(dev);
if (ret)
        goto out;
buf = kmalloc(len, GFP_KERNEL);
if (!buf)
        goto out;       /* ret is still 0 */
```

A failure is a NULL test of a pointer that only ever holds allocations,
`IS_ERR()`, or `< 0` on the result of a call. The variable has to be zero
on every path to the test, from its initializer or from an earlier test of
it. An explicit `ret = 0;` statement is taken to say that zero is meant.
Zero can be the right result on such a path, so the warning needs a look at
each hit and stays out of the umbrella.

`-Wlinux-kernel-ptr-err-zero` is available separately. It diagnoses
`PTR_ERR(p)` where `p` is NULL: in the branch of `if (!p)`, and in the
branch of `if (IS_ERR_OR_NULL(p))`, where NULL is one of the two cases.
`PTR_ERR(NULL)` is 0, so the failure is returned as success. Some callers
mean exactly that for a NULL that stands for "not there".

`-Wlinux-kernel-error-pointer-deref` is available separately. It diagnoses
`p->member` where `p` holds the result of an error pointer function and the
function tests `p` nowhere, neither with `IS_ERR()` nor for NULL. The callee
may be known not to fail at that call, which the check cannot see.

`-Wlinux-kernel-deref-before-check` is available separately. It diagnoses a
NULL test of a local pointer or pointer parameter that every path to the
test has already read or written through:

```c
len = req->len;
if (!req)
        return -EINVAL;
```

Either the test is dead or the dereference is unsafe. Taking the address of
a member (`&p->member`, `container_of()`) is not an access, and a test that
is part of a macro body is ignored. Old code has many dead tests of this
kind, so the warning is most useful on changed lines.

`-Wlinux-kernel-cleanup-escape` is available separately. It diagnoses
`obj->field = p;` and `*out = p;` where `p` was declared with `__free()` and
the function neither uses `no_free_ptr()` on it nor stores NULL in it. For a
cleanup function that drops a reference rather than freeing memory the stored
pointer may be kept alive by something else, which the check cannot see.

`-Wlinux-kernel-irq-zero` is available separately. It diagnoses comparisons
of a platform IRQ result with zero, such as `irq <= 0`. These lose the
returned errno but do not miss the failure, and old drivers contain many of
them.

`-Wlinux-kernel-errno` is available separately. It diagnoses a positive errno
constant returned by a signed integer function and a negative errno returned
by an unsigned integer function. A complete Linux 5.10 scan produced 474 of
these diagnostics, including many functions whose positive return values are
intentional status codes. The check is therefore too broad for the umbrella
until it can identify errno-returning functions more accurately.

Each kernel-specific subgroup can be enabled or disabled independently. For
example:

```console
$ clang -ffreestanding -Wlinux-kernel \
    -Wno-linux-kernel-error-pointer -c driver.c
```

To build a Linux kernel with the profile, point Kbuild at this Clang tree and
pass the warning through `KCFLAGS`:

```console
$ make LLVM=1 CC=/path/to/llvm-build/bin/clang KCFLAGS=-Wlinux-kernel
```

For an API-contract-only scan, disable the path-sensitive warning from the
umbrella:

```console
$ make LLVM=1 CC=/path/to/llvm-build/bin/clang \
    KCFLAGS='-Wlinux-kernel -Wno-conditional-uninitialized'
```

## Declaring a contract

The checks know a built-in table of kernel functions. A declaration can also
state its contract itself, which lets the kernel describe APIs that the table
does not list:

```c
#define __returns_err_ptr \
  __attribute__((annotate("linux_kernel::returns_err_ptr")))

__returns_err_ptr struct clk *my_clk_get(struct device *dev);
```

The recognized annotations are `linux_kernel::returns_err_ptr`,
`linux_kernel::returns_null_on_failure`,
`linux_kernel::returns_uncopied_bytes` and
`linux_kernel::returns_irq_or_errno`. An annotation takes precedence over the
table.

## Inferred contracts

The table and the annotations cover the well known APIs. For every other
function that returns a pointer, the checks work out the convention from the
function body when the translation unit has one:

- a function that returns `ERR_PTR()` or the result of an error pointer
  function, and otherwise only valid pointers, returns error pointers;
- a function that returns `NULL` or the unchecked result of an allocation,
  and never an error pointer, returns NULL on failure.

A value read from memory may be NULL, so it rules out the first convention
but not the second. A value that the function tests for NULL before it
returns it is valid. A function that returns nothing but `ERR_PTR()` or
nothing but `NULL` is a stub for another configuration and gets no contract,
and neither does a function that mixes both conventions. The diagnostic
carries a note that points at the function whose contract was inferred.

For a function that is defined in another translation unit, two passes over
the kernel are needed. The first collects facts, the second uses their
closure:

```console
$ make LLVM=1 CC=clang KCFLAGS=-flinux-kernel-emit-facts=$PWD/facts
$ clang/utils/linux-kernel/infer-contracts.py -o contracts facts
$ make LLVM=1 CC=clang \
    KCFLAGS='-Wlinux-kernel -flinux-kernel-contracts=$PWD/contracts'
```

The facts file gets one line for each function with external linkage: where
its return values come from, and which functions it calls whenever it runs
to its end. `infer-contracts.py --explain <function>` shows how an answer
came about. The second list is what `alpha.linux.AtomicSleep` uses to know
that a function in another translation unit sleeps.

## Static analyzer

Whether a call may sleep while a spinlock is held depends on the path, so
that check is a static analyzer checker and not a warning:

```sh
clang --analyze -Xclang -analyzer-checker=alpha.linux.AtomicSleep ...
```

`alpha.linux.AtomicSleep` tracks spinlocks and rwlocks (through
`_raw_spin_lock()` and the other functions the kernel's inline wrappers end
in), `rcu_read_lock()`, `preempt_disable()` and `local_bh_disable()` along a
path. While one of them is open it reports `might_sleep()`, a list of
functions that always sleep, and a call to a function without a visible body
that is passed gfp flags known to allow direct reclaim. It sees one
translation unit, so both the lock and the sleeping call have to be on one
path in it. With `-flinux-kernel-contracts=` it also knows the functions of
other translation units that always sleep.

`alpha.linux.LockBalance` reports a spinlock, mutex or rwsem that a function
takes and still holds where it returns a failure while another path releases
it, or that it holds on one return path and releases on another with the
same kind of result. A lock that is held where the function succeeds and
released where it fails is taken to be the purpose of the function, as are
the locks of a function with "lock" in its name or with a capability
annotation.

`alpha.linux.NodeRef` reports a device tree node that a function got from
one of the lookup functions of `<linux/of.h>` and that goes out of reach
without `of_node_put()`. Storing or returning the node hands the reference
on. Passing it to a function does not.

Neither checker runs cleanup functions, because the analyzer does not. Locks
taken by `guard()` and nodes kept in a `__free(device_node)` variable are
left alone.

The three checkers share `alpha.linux.KernelModel`, which has two options
for a sweep over a whole kernel:

```sh
-analyzer-config alpha.linux.KernelModel:SkipIrrelevant=true
-analyzer-config alpha.linux.KernelModel:LikelyStaticBranches=true
```

The first ends the analysis of a function in which none of the enabled
checkers can find anything, because neither it nor any function it calls
that has a body takes a lock, enters an atomic section or looks up a node.
The second takes a static branch the way its `likely()` or `unlikely()`
annotation says instead of both ways.

## API provenance

The API checks follow values through direct calls, local initializers, simple
assignments to locals and direct structure fields, casts, GNU statement
expressions, `_Generic`, and `__builtin_choose_expr`. Taking the address of a
tracked local, writing it from inline assembly, or assigning it on
control-flow-dependent paths clears the inferred contract. This keeps the
diagnostics conservative when a value may have changed through a path the
analysis cannot model. The supported cases cover allocation macro expansions
used by current kernels and older stable kernels without requiring changes to
kernel headers.

A negative NULL test next to an `IS_ERR()` or `IS_ERR_OR_NULL()` test of the
same variable is treated as one combined guard. This avoids diagnosing the
defensive `!pointer || IS_ERR(pointer)` form.

NULL tests inside the kernel's `WARN*()` and `BUG_ON()` assertion macros are
also ignored. Those tests state an invariant after normal error handling; they
do not try to detect and recover from an API failure.

The constant-argument check for `ERR_PTR()` applies to explicit calls in source
and deliberately ignores calls expanded from a macro. Some kernel macros use
`ERR_PTR(0)` internally to form an optional null argument, and reporting those
expansions points at an innocent macro invocation rather than at the definition
that chose the value.

The built-in contract table is intentionally limited to APIs whose failure
convention is stable and unambiguous. Wrappers that change or preserve a
contract may need to be added to the table before Clang can diagnose their
callers. As with every heuristic warning, review the full control flow before
changing code, and use a narrow `-Wno-linux-kernel-*` option when a subsystem
intentionally uses a different convention.

## Examples

```c
bool initialize(void)
{
        /* Warns: -EINVAL converts to true. */
        return -EINVAL;
}

int copy_request(void *dst, const void __user *src, size_t size)
{
        int left = copy_from_user(dst, src, size);

        /* Warns: left is a residual byte count and cannot be negative. */
        if (left < 0)
                return left;
        return left ? -EFAULT : 0;
}

int allocate(size_t size)
{
        void *buffer = kmalloc(size, GFP_KERNEL);

        /* Warns: kmalloc() fails with NULL, not ERR_PTR(). */
        if (IS_ERR(buffer))
                return PTR_ERR(buffer);
        return buffer ? 0 : -ENOMEM;
}
```
