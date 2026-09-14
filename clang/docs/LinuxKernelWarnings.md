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
- `-Wlinux-kernel-irq` diagnoses boolean and zero-inclusive failure tests of
  the platform IRQ lookup helpers. These helpers return a positive IRQ number
  or a negative errno, so callers must test for a negative value and preserve
  that errno.
- `-Wconditional-uninitialized` supplies the existing path-sensitive analysis
  that is especially useful for kernel cleanup labels and configuration-driven
  control flow.

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
