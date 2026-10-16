# DMA-buf mapping RFC Clang checks

This loadable clang-tidy module checks contracts introduced by the 26-patch
DMA-buf mapping-type/PAL RFC (`dmabuf_map_type_jgg@nvidia.com`).  It is kept
out of the default Linux kernel checks because the API is still under review.

The primary check is the cross-patch `match_mapping()` contract.  Patch 3
calls the exporter before initializing the attachment or taking `dma_resv`,
while the callbacks added in patches 11 and 12 consume attachment state and
lock-protected exporter state.  DMABUF-RFC-02 through DMABUF-RFC-05 report the
four sides of that contradiction.  The remaining diagnostics retain the
secondary lifetime findings from the same review.

The checker reports:

- nullable importer operations used by the compatibility attach wrapper;
- `match_mapping()` invocation before attachment initialization;
- disagreement between core and callback `dma_resv` expectations;
- match callbacks consuming unavailable importer state;
- PAL exporters returning ranges after revocation;
- error pointers or half-initialized PAL state published across an unlock;
- PAL storage left published after unmap; and
- `kvmalloc()`/`kfree()` callback-pair mismatches.

Build the module with the LLVM tree or with the standalone development build:

```sh
cmake -S standalone -B build -G Ninja \
  -DLLVM_DIR=/path/to/llvm/lib/cmake/llvm \
  -DClang_DIR=/path/to/llvm/lib/cmake/clang
ninja -C build
```

Load it into the matching clang-tidy binary:

```sh
clang-tidy --load build/DmaBufRfcTidyModule.dylib \
  -checks=-\*,linuxkernel-dmabuf-mapping-rfc source.c -- <compile flags>
```

The plugin and clang-tidy must come from ABI-compatible LLVM builds.

