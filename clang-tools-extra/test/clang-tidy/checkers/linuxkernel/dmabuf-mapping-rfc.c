// REQUIRES: plugins
// RUN: %check_clang_tidy -std=c11 -load=%llvmshlibdir/DmaBufRfcTidyModule%pluginext %s linuxkernel-dmabuf-mapping-rfc %t

typedef unsigned long size_t;

#define NULL ((void *)0)
#define IS_ERR(ptr) ((unsigned long)(ptr) > (unsigned long)-4096)

struct dma_buf_attachment;
struct dma_buf_match_args;

struct dma_buf_attach_ops {
  int allow_peer2peer;
};

struct dma_buf_ops {
  int (*match_mapping)(struct dma_buf_match_args *args);
};

struct dma_buf {
  struct dma_buf_ops *ops;
  void *resv;
  void *priv;
};

struct dma_buf_attachment {
  struct dma_buf *dmabuf;
  const struct dma_buf_attach_ops *importer_ops;
  void *importer_priv;
};

struct dma_buf_match_args {
  struct dma_buf *dmabuf;
  struct dma_buf_attachment *attach;
};

struct dma_buf_phys_list {
  size_t length;
  unsigned long phys[];
};

struct vfio_priv {
  int revoked;
  size_t nr_ranges;
  unsigned long *phys_vec;
};

struct iopt_pages {
  struct {
    struct dma_buf_attachment *attach;
    struct dma_buf_phys_list *exp_phys;
  } dmabuf;
};

void *kzalloc(size_t, int);
void *__kvmalloc_node_noprof(size_t, int, int);
void kfree(void *);
void kvfree(void *);
void memcpy(void *, const void *, size_t);
void dma_resv_lock(void *, void *);
void dma_resv_unlock(void *);
void *dma_buf_attach_adev(struct dma_buf_attachment *);
struct dma_buf_phys_list *
dma_buf_pal_map_phys(struct dma_buf_attachment *);
void dma_buf_pal_unmap_phys(struct dma_buf_attachment *,
                            struct dma_buf_phys_list *);

#define kvmalloc(size, flags) __kvmalloc_node_noprof(size, 1, flags)
#define dma_resv_assert_held(resv) do { (void)(resv); } while (0)

struct dma_buf_attachment *
dma_buf_dynamic_attach(struct dma_buf *dmabuf, void *dev,
                       const struct dma_buf_attach_ops *importer_ops,
                       void *importer_priv) {
  int p2p = importer_ops->allow_peer2peer;
  // CHECK-MESSAGES: :[[@LINE-1]]:27: warning: DMABUF-RFC-01:
  return p2p ? (struct dma_buf_attachment *)dev : NULL;
}

struct dma_buf_attachment *
dma_buf_mapping_attach(struct dma_buf *dmabuf,
                       const struct dma_buf_attach_ops *importer_ops,
                       void *importer_priv) {
  struct dma_buf_match_args args = { .dmabuf = dmabuf };
  struct dma_buf_attachment *attach = kzalloc(sizeof(*attach), 0);

  args.attach = attach;
  dmabuf->ops->match_mapping(&args);
  // CHECK-MESSAGES: :[[@LINE-1]]:3: warning: DMABUF-RFC-02:
  // CHECK-MESSAGES: :[[@LINE-2]]:3: warning: DMABUF-RFC-03:
  attach->dmabuf = dmabuf;
  attach->importer_ops = importer_ops;
  attach->importer_priv = importer_priv;
  return attach;
}

static int amdgpu_dma_buf_match_mapping(struct dma_buf_match_args *args) {
  dma_buf_attach_adev(args->attach);
  // CHECK-MESSAGES: :[[@LINE-1]]:3: warning: DMABUF-RFC-04:
  return 0;
}

static int vfio_pci_dma_buf_match_mapping(struct dma_buf_match_args *args) {
  dma_resv_assert_held(args->dmabuf->resv);
  // CHECK-MESSAGES: :[[@LINE-1]]:3: warning: DMABUF-RFC-05:
  return 0;
}

static void unrelated_lock_assert(struct dma_buf *dmabuf) {
  dma_resv_assert_held(dmabuf->resv);
}

static struct dma_buf_phys_list *
vfio_pci_dma_pal_map_phys(struct dma_buf_attachment *attach) {
  struct vfio_priv *priv = attach->dmabuf->priv;
  struct dma_buf_phys_list *phys = kvmalloc(sizeof(*phys), 0);
  memcpy(phys->phys, priv->phys_vec, sizeof(*priv->phys_vec));
  // CHECK-MESSAGES: :[[@LINE-1]]:28: warning: DMABUF-RFC-06:
  return phys;
}

static void
vfio_pci_dma_pal_unmap_phys(struct dma_buf_attachment *attach,
                            struct dma_buf_phys_list *phys) {
  kvfree(phys);
}

static struct dma_buf_phys_list *
iommufd_dma_pal_map_phys(struct dma_buf_attachment *attach) {
  return kvmalloc(sizeof(struct dma_buf_phys_list), 0);
}

static void
iommufd_dma_pal_unmap_phys(struct dma_buf_attachment *attach,
                           struct dma_buf_phys_list *phys) {
  kfree(phys);
  // CHECK-MESSAGES: :[[@LINE-1]]:3: warning: DMABUF-RFC-10:
}

static int iopt_map_dmabuf(struct iopt_pages *pages,
                           struct dma_buf_attachment *attach) {
  struct dma_buf *dmabuf = attach->dmabuf;
  int rc = 0;

  pages->dmabuf.exp_phys = dma_buf_pal_map_phys(attach);
  // CHECK-MESSAGES: :[[@LINE-1]]:26: warning: DMABUF-RFC-07:
  if (IS_ERR(pages->dmabuf.exp_phys)) {
    rc = -1;
    goto err_detach;
  }
  dma_resv_unlock(dmabuf->resv);
  // CHECK-MESSAGES: :[[@LINE-1]]:3: warning: DMABUF-RFC-08:
  pages->dmabuf.attach = attach;
  return 0;

err_detach:
  dma_resv_unlock(dmabuf->resv);
  return rc;
}

static void iopt_release_pages(struct iopt_pages *pages) {
  struct dma_buf *dmabuf = pages->dmabuf.attach->dmabuf;

  dma_resv_lock(dmabuf->resv, NULL);
  dma_buf_pal_unmap_phys(pages->dmabuf.attach, pages->dmabuf.exp_phys);
  dma_resv_unlock(dmabuf->resv);
  // CHECK-MESSAGES: :[[@LINE-1]]:3: warning: DMABUF-RFC-09:
}

/* Negative controls for guards and corrected lifetime transitions. */
struct dma_buf_attachment *
dma_buf_sgt_dynamic_attach(struct dma_buf *dmabuf, void *dev,
                           const struct dma_buf_attach_ops *importer_ops,
                           void *importer_priv) {
  int p2p = importer_ops && importer_ops->allow_peer2peer;
  return p2p ? (struct dma_buf_attachment *)dev : NULL;
}

static struct dma_buf_phys_list *
fixed_dma_pal_map_phys(struct dma_buf_attachment *attach) {
  struct vfio_priv *priv = attach->dmabuf->priv;
  struct dma_buf_phys_list *phys;

  if (priv->revoked)
    return NULL;
  phys = kvmalloc(sizeof(*phys), 0);
  memcpy(phys->phys, priv->phys_vec, sizeof(*priv->phys_vec));
  return phys;
}

static void fixed_dma_pal_unmap_phys(struct dma_buf_attachment *attach,
                                     struct dma_buf_phys_list *phys) {
  kvfree(phys);
}

static void fixed_release_pages(struct iopt_pages *pages) {
  struct dma_buf *dmabuf = pages->dmabuf.attach->dmabuf;

  dma_resv_lock(dmabuf->resv, NULL);
  dma_buf_pal_unmap_phys(pages->dmabuf.attach, pages->dmabuf.exp_phys);
  pages->dmabuf.exp_phys = NULL;
  dma_resv_unlock(dmabuf->resv);
}

static int fixed_map_error(struct iopt_pages *pages,
                           struct dma_buf_attachment *attach) {
  pages->dmabuf.exp_phys = dma_buf_pal_map_phys(attach);
  if (IS_ERR(pages->dmabuf.exp_phys)) {
    pages->dmabuf.exp_phys = NULL;
    dma_resv_unlock(attach->dmabuf->resv);
    return -1;
  }
  dma_resv_unlock(attach->dmabuf->resv);
  return 0;
}

