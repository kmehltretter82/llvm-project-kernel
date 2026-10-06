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
is part of a macro body is ignored. An access through a pointer to a part
is one, though: after `struct stream *s = &ext->stream;` the read of
`s->index` reads through `ext`, as long as neither variable is given
another value anywhere in the function. Old code has many dead tests of
this kind, so the warning is most useful on changed lines.

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

### Checks that follow a path

The groups in this section are available separately. They are not part of
the umbrella yet.

Three of them walk single paths through a function. A dataflow over facts
that hold on every path cannot find a pointer that is NULL on one path to a
dereference and fine on the others. The search starts where a test or a
call establishes something and follows each path with what assignments and
branches have pinned down on the way: the sign and, where known, the value
of local variables and of member chains such as `dev->priv`, and the
outcome of conditions without side effects that occur more than once. A
branch that the path already decides is followed in one direction only. A
candidate is confirmed by a second search from the entry of the function,
so that what the code before the test establishes counts as well:

```c
int n = 0;

if (p)
        n = p->count;
for (i = 0; i < n; i++)         /* not entered when p is NULL */
        sum += p->item[i];
```

A call makes the search forget the members of an object that the callee may
change. If the body of the callee is in the translation unit, that is the
members it or its callees store to. Otherwise it is every member of an
object that the call is given. The search stops at a fixed budget and
reports nothing then.

- `-Wlinux-kernel-deref-after-check` diagnoses a pointer that is read or
  written through on a path that left a NULL test through the outcome "is
  NULL":

  ```c
  if (!dev->priv)
          dev_warn(dev->parent, "no private data\n");
  dev->priv->count++;
  ```

  The pointer can be a local variable, a parameter or a member chain. The
  dereference can also be in a function that is handed the pointer and reads
  or writes through its parameter before its first branch. A branch that
  the configuration has decided is none: the `if (__builtin_constant_p(fmt))`
  inside `dev_err()` and the `while (0)` at the end of a macro do not end
  that part of the function. Tests inside
  macros do not count: `dev_err()`, `kfree()` and many others test whatever
  they get. The test says that the author expects NULL. If NULL cannot
  happen there, the test is what is wrong.
- `-Wlinux-kernel-ptr-err-valid` diagnoses `PTR_ERR(p)` on a path where
  `IS_ERR(p)` was false. This is what a shared error label does when one of
  the jumps to it comes from another failure than that of `p`.
- `-Wlinux-kernel-error-pointer-zero` diagnoses `ERR_PTR(err)` on a path
  where a test found `err` to be zero, in a function that returns objects
  on other paths and NULL nowhere. Its callers test the result with
  `IS_ERR()` and take NULL for an object.
- `-Wlinux-kernel-missing-unwind` diagnoses an error return that keeps a
  resource which the function releases on another path behind the
  acquisition:

  ```c
  ret = clk_prepare_enable(priv->clk);
  if (ret)
          return ret;
  ret = setup(priv);
  if (ret)
          return ret;             /* the clock stays enabled */
  ...
  err:
          clk_disable_unprepare(priv->clk);
          return ret;
  ```

  About sixty pairs are known: clocks, regulators, runtime PM, PHYs,
  interrupts, PCI devices and regions, firmware, mutexes, spinlocks and
  semaphores, `ioremap()`, workqueues, crypto transforms, device tree nodes
  and the allocators. A path ends where the acquisition has failed, where
  the resource is released, at a `devm_` call that is given the object, and
  at a call that is given the object and cleans up, by its name or because
  its body releases a resource of that kind. A function that never releases
  the resource itself is left alone: a remove callback or devres does that
  for it. So is an acquisition that takes back what the function released
  before (`unlock(); ...; lock();`), and the branches that lead to the
  acquisition alone are taken to hold for the rest of the function
  (`if (c) get(); ... if (c) put();`).
- `-Wlinux-kernel-memory-leak` diagnoses a return at which a local variable
  still holds the result of `kmalloc()` or one of its relatives, and the
  path has neither freed the memory nor stored the pointer nor handed it to
  a function that may keep it. Whether a function may keep a pointer is
  taken from its body where the translation unit has it, and from a list of
  kernel functions that only read or fill a buffer. Every other call that
  is given the pointer ends the path.

Three more are dataflow checks over the control flow graph:

- `-Wlinux-kernel-duplicate-check` diagnoses a test of a local variable
  against zero whose outcome an earlier test has decided on every path,
  with the variable unchanged since:

  ```c
  err = step_one();
  if (err)
          goto out;
  step_two();                     /* "err =" is missing */
  if (err)
          goto out;
  ```

  It is not given when the source has an assignment to the variable or a
  preprocessor conditional between the two tests, because the assignment
  may be in code that this configuration does not compile, and not for
  `else if` chains and repeated tests within one condition.
- `-Wlinux-kernel-use-after-free` diagnoses a dereference, or a second
  free, of a variable or member chain that every path has handed to
  `kfree()` or one of its relatives since it was last assigned. A loop that
  frees the element it stands on is the common case:

  ```c
  list_for_each_entry(item, &head, list)
          kfree(item);            /* the loop reads item->list.next */
  ```

The rest look at single expressions and calls:

- `-Wzero-extended-complement` is not specific to the kernel. It diagnoses
  `x & ~mask` and `x &= ~mask` where `x` has more bits than the unsigned
  `mask`. The complement is computed in the width of the mask and then
  zero-extended, which clears the upper bits of `x` along with the bits of
  the mask. On a 32-bit kernel `BIT()` and `~0UL` are such masks:

  ```c
  u64 ts;

  ts &= ~(BIT(8) - 1);            /* 32-bit: clears bits 63 to 32 as well */
  ```

  It is not given when the result is converted back to the width of the
  mask, when the other operand was itself widened from that width, or for
  `~0U`, which says how many bits are meant.
- `-Wlinux-kernel-bitops-cast` diagnoses `set_bit()`, `test_bit()`,
  `find_first_bit()`, `bitmap_zero()` and their relatives when a cast hands
  them the address of an integer that is narrower than `unsigned long`. The
  functions read and write a whole `unsigned long`, and on a big-endian
  machine they see other bits than the code that uses the integer as a
  number. On a 32-bit big-endian target it also diagnoses the address of a
  64-bit integer, whose two halves are in the other order there.
- `-Wlinux-kernel-struct-leak` diagnoses `copy_to_user(to, &s, sizeof(s))`,
  `nla_put()` and `copy_to_iter()` of a local structure that has padding
  and that the function only ever fills member by member. The padding goes
  out with what was on the stack. The structure counts as cleared when it
  has an initializer, when it is assigned as a whole, and when its address
  is given to `memset()` or to any function that the translation unit has
  no body of. The layout is that of the target, so a hole that only one ABI
  has is found when that ABI is compiled for.
- `-Wlinux-kernel-buffer-size` diagnoses `snprintf()`, `scnprintf()` and
  their `v` variants when the size is a constant, or a constant minus what
  was written so far, that is larger than the array the buffer argument
  points into.
- `-Wlinux-kernel-off-by-one` diagnoses `a[i]` where the bounds test on the
  way lets `i` be the number of elements: `if (i > ARRAY_SIZE(a)) return;`,
  or the same against the member that `__counted_by()` names for a flexible
  array.
- `-Wlinux-kernel-unchecked-allocation` diagnoses `p->member` where `p` was
  given the result of `kmalloc()` or one of its relatives directly and the
  function tests `p` nowhere. An allocation with `__GFP_NOFAIL` is left
  alone.
- `-Wlinux-kernel-indent` diagnoses a statement that starts in another
  column than the statement before it in the same block. The second one was
  often meant to be under the `if` above it.

`-Wlinux-kernel-experimental` is the group of checks that are being tried
out. `-flinux-kernel-experimental=<name>,...` selects them, and `all`
selects every one. The group alone turns nothing on. A check moves to a
group of its own once a kernel scan has shown what it finds. The names:

- `error-deref-after-check`: the dereference rule for a pointer that
  `IS_ERR()` found to be an error pointer.
- `error-deref-path`: the result of a function that returns an error pointer
  on failure is dereferenced, or handed to a function that dereferences it,
  on a path that has not tested it. This is the path version of
  `-Wlinux-kernel-error-pointer-deref`, which gives up when the assignment
  is inside a branch.
- `error-pointer-null-test`: a pointer that `IS_ERR()` found to be an error
  pointer comes to a NULL test, as in `out: if (p) put(p);`. It is reported
  when the pointer is then used where only a pointer that is not NULL gets
  to, and when nothing else looks at it before the function returns, so that
  what the NULL test guards is skipped for the failure.
- `uninit-output`: a local variable is read although the function that was
  given its address may not have written to it. The compiler works out, for
  each function with a body, for which return values a pointer parameter is
  left unwritten, and follows the caller's paths on which the call returned
  such a value. `ret = read(&val); if (ret) return ret;` is fine,
  `read(&val); use(val);` is not if `read()` can fail before it writes.
  Where the function returns a constant without writing, the caller's paths
  are followed for that value alone, so `if (index == -1) return;` deals
  with a `return -1;`. Several things are taken on trust to keep the check
  quiet: a loop that fills the buffer runs, a size or count parameter is
  what the caller needs unless the call passes a constant, an assertion
  (`if (WARN_ON(...)) return;`) does not fire, a path that writes another
  output parameter has told the caller what to look at, and a caller that
  branches on another output of the same call knows what it is doing.
- `null-argument`: a literal `NULL` is passed for a parameter that the
  callee dereferences before its first branch and tests nowhere.
- `container-of-null`: a NULL test of the result of `container_of()`. The
  entry macros of `<linux/list.h>` never yield NULL, in particular not for
  an empty list and not after the last round of `list_for_each_entry()`.
  A plain `container_of()` is reported if the member is not at offset zero.
- `direct-return`: an error path returns although an error path before it
  and one after it jump to cleanup code, the later one to the same code or
  to more of it, and nothing in between calls what that code calls. This
  check knows no resources, the function's own error handling is the
  evidence. Cleanup code is a label whose code calls something and then
  returns an error code or a variable that is named like one. A label that
  leads to another way of doing the work (`slow_path: return do_slow();`)
  or that only prints is not. The return is left alone if it reports the
  failure of the very thing that the label would free, if its block hands
  that thing to someone (`si->buf = buf; return -EAGAIN;`), or if a
  sibling of the cleanup function was called on the way with the same
  arguments (`nla_nest_end()` where the label has `nla_nest_cancel()`).
- `unwind-return-call`: `-Wlinux-kernel-missing-unwind` for `return
  register(priv);` and for `return ret;` with a status that no test has
  looked at. If that call fails, the resource is still held.
- `unwind-far`: `-Wlinux-kernel-missing-unwind` for a function that
  releases the resource nowhere, when another function of the translation
  unit releases what the same structure member holds, typically the remove
  callback, or `exit` for the `init` of a PHY. It is reported at the end of
  the translation unit, for a return with an error and, together with
  `unwind-return-call`, for `return ret;` behind the last call of the
  function. Not reported: a function whose callers, up to
  three levels, release the member or name the releasing function (a
  destructor that is registered, such as `card->private_free`), a function
  that other translation units can call unless this one uses it as a
  callback, locks (one callback takes them and another drops them by
  design), and memory, which goes where the structure goes. A function
  that both acquires and releases the member is not taken as the one that
  tears down.

Two more names change how the path checks work and are not part of `all`:
`path-notes` adds a note for each branch between the test and the misuse,
and `unconfirmed-paths` reports candidates without the second search from
the function entry.

## Architectures without a code generator

The kernel supports architectures that LLVM has no backend for. Their code
can still be checked: the frontend only needs the C data model of the
target. The triples `alpha`, `hppa`, `hppa64`, `sh4` (and the other `sh`
names, with `eb` for big-endian), `microblaze`, `microblazeel`, `nios2` and
`or1k` select a target description that knows the sizes and alignments of
the types as GCC has them, the byte order and the predefined macros that
kernel headers test, and GCC's builtin functions for Alpha. Register names
and machine-specific constraint letters in inline assembly are accepted as
written.

```console
$ clang --target=sh4-linux-gnu -fsyntax-only ...
```

Anything that needs code generation fails with "unable to create target".

`-flinux-kernel-lenient-asm` does the same for the inline assembly of a
target that clang does know but describes incompletely: an unknown
constraint letter is taken for a register class, unknown register names
are accepted, and an operand escape that only the target's assembler
output knows (`%@` on m68k) no longer stops the compilation.

A kernel build for such a target has to be configured and prepared by
another compiler, because Kbuild probes the compiler and generates headers
by compiling. `scan-cc-host` in the scan tooling does that: a cross GCC
answers everything that has to produce output, and the `.c` to `.o`
compiles are replayed with this compiler and `-fsyntax-only`.

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

A second line says what the function does with its pointer parameters: which
it dereferences before its first branch, which it hands to a function of
another translation unit there, and which it can leave unwritten when it
returns, with the kind of return value for which it does. The closure turns
these into `derefs` and `nowrite` lines of the contracts file. With them the
checks that ask about a callee, that is the dereference of a pointer that
was found to be NULL, `null-argument`, `error-deref-path` and
`uninit-output`, give the same answer for a function of another file as for
one whose body is at hand. Every definition of a function has to agree: a
weak default that tests its argument takes the contract away from the
override that does not.

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
