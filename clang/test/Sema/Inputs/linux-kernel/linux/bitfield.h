/* What FIELD_PREP() of the kernel's <linux/bitfield.h> does to see whether a
 * constant fits its field, without the build assertion around it. */
#define __bf_shf(x) (__builtin_ffsll(x) - 1)
#define FIELD_PREP(_mask, _val)                                                \
  ({                                                                           \
    (void)(__builtin_constant_p(_val)                                          \
               ? ~((_mask) >> __bf_shf(_mask)) & (0 + (_val))                  \
               : 0);                                                           \
    ((__typeof__(_mask))(_val) << __bf_shf(_mask)) & (_mask);                  \
  })
