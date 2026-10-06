// A loop that looks for something and runs to its end leaves its index one
// past the last element, and its list cursor at the head of the list, which
// is no entry.  What uses them behind the loop has to know that the loop
// found something.
//
// RUN: %clang_cc1 -fsyntax-only -ffreestanding -Wlinux-kernel-experimental \
// RUN:   -flinux-kernel-experimental=index-past-end,cursor-past-end -verify %s
// RUN: %clang_cc1 -fsyntax-only -ffreestanding -Wall -verify=wall %s

// wall-no-diagnostics

typedef _Bool bool;
typedef unsigned long size_t;
#define NULL ((void *)0)
#define true 1
#define false 0
#define EINVAL 22
#define ENOENT 2
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define unlikely(x) __builtin_expect(!!(x), 0)
#define offsetof(TYPE, MEMBER) __builtin_offsetof(TYPE, MEMBER)
#define container_of(ptr, type, member) ({ \
  void *__mptr = (void *)(ptr); \
  ((type *)(__mptr - offsetof(type, member))); })

struct list_head {
  struct list_head *next, *prev;
};

static inline int list_is_head(const struct list_head *list,
                               const struct list_head *head) {
  return list == head;
}

void list_add(struct list_head *item, struct list_head *head);

#define list_entry(ptr, type, member) container_of(ptr, type, member)
#define list_first_entry(ptr, type, member) \
  list_entry((ptr)->next, type, member)
#define list_next_entry(pos, member) \
  list_entry((pos)->member.next, typeof(*(pos)), member)
#define list_entry_is_head(pos, head, member) \
  list_is_head(&pos->member, (head))
#define list_for_each_entry(pos, head, member) \
  for (pos = list_first_entry(head, typeof(*pos), member); \
       !list_entry_is_head(pos, head, member); \
       pos = list_next_entry(pos, member))
#define list_for_each_entry_rcu(pos, head, member) \
  for (pos = list_entry((head)->next, typeof(*pos), member); \
       &pos->member != (head); \
       pos = list_entry(pos->member.next, typeof(*pos), member))
#define list_for_each_entry_continue(pos, head, member) \
  for (pos = list_next_entry(pos, member); \
       !list_entry_is_head(pos, head, member); \
       pos = list_next_entry(pos, member))

struct rate {
  int id;
  int value;
};

static const struct rate rates[] = {
  { 1, 100 }, { 2, 200 }, { 3, 400 }, { 4, 800 },
};

struct item {
  struct list_head list;
  struct list_head children;
  int id;
  int value;
};

struct bag {
  int count;
  int slots[] __attribute__((counted_by(count)));
};

unsigned long find_next_bit(const unsigned long *addr, unsigned long size,
                            unsigned long offset);
#define for_each_set_bit(bit, addr, size) \
  for ((bit) = 0; \
       (bit) = find_next_bit((addr), (size), (bit)), (bit) < (size); (bit)++)

void note(int n);
int get(void);

static int item_value(const struct item *it) {
  return it->value;
}

void item_put(struct item *it);

// ---------------------------------------------------------------------------
// The index.

int search(int id) {
  int i;

  for (i = 0; i < ARRAY_SIZE(rates); i++) // expected-note {{the loop ends here if nothing has left it before}}
    if (rates[i].id == id)
      break;
  return rates[i].value;
// expected-warning@-1 {{'i' is the index into 'rates' here, but on this path the loop has run to its end, which leaves 'i' at 4, the number of elements (experimental check 'index-past-end')}}
}

int search_while(int id) {
  unsigned int i = 0;

  while (i < ARRAY_SIZE(rates) && rates[i].id != id) // expected-note {{the loop ends here if nothing has left it before}}
    i++;
  return rates[i].value;
// expected-warning@-1 {{'i' is the index into 'rates' here, but on this path the loop has run to its end, which leaves 'i' at 4, the number of elements (experimental check 'index-past-end')}}
}

// Every pass goes on to the next one: the loop always runs to its end.
int after_all(int *sum) {
  int vals[4];
  int i;

  for (i = 0; i < 4; i++) // expected-note {{the loop ends here if nothing has left it before}}
    vals[i] = get();
  vals[i] = 0;
// expected-warning@-1 {{'i' is the index into 'vals' here, but on this path the loop has run to its end, which leaves 'i' at 4, the number of elements (experimental check 'index-past-end')}}
  return vals[0];
}

int search_counted(struct bag *b, int id) {
  int i;

  for (i = 0; i < b->count; i++) // expected-note {{the loop ends here if nothing has left it before}}
    if (b->slots[i] == id)
      break;
  b->slots[i] = id;
// expected-warning@-1 {{'i' is the index into 'b->slots' here, but on this path the loop has run to its end, which leaves 'i' at 'b->count', the number of elements (experimental check 'index-past-end')}}
  return i;
}

int tested_and_used(unsigned int i) {
  if (i >= ARRAY_SIZE(rates)) // expected-note {{the test is here}}
    note(rates[i].value);
// expected-warning@-1 {{'i' is the index into 'rates' here, but on this path a test has found 'i' not to be below 4, the number of elements (experimental check 'index-past-end')}}
  return 0;
}

int search_bits(const unsigned long *mask, int id) {
  unsigned long bit;

  for_each_set_bit(bit, mask, ARRAY_SIZE(rates)) // expected-note {{the loop ends here if nothing has left it before}}
    if (rates[bit].id == id)
      break;
  return rates[bit].value;
// expected-warning@-1 {{'bit' is the index into 'rates' here, but on this path the loop has run to its end, which leaves 'bit' at 4, the number of elements (experimental check 'index-past-end')}}
}

// The second array has as many elements as the first.
static int limits[ARRAY_SIZE(rates)];

int search_other(int id) {
  int i;

  for (i = 0; i < ARRAY_SIZE(rates); i++) // expected-note {{the loop ends here if nothing has left it before}}
    if (rates[i].id == id)
      break;
  return limits[i];
// expected-warning@-1 {{'i' is the index into 'limits' here, but on this path the loop has run to its end, which leaves 'i' at 4, the number of elements (experimental check 'index-past-end')}}
}

// The flag is set where the loop is left, and only there.
int search_flag_wrong(int id) {
  bool seen = false;
  int i;

  for (i = 0; i < ARRAY_SIZE(rates); i++) { // expected-note {{the loop ends here if nothing has left it before}}
    if (rates[i].id == id)
      seen = true;
  }
  if (!seen)
    return -EINVAL;
  return rates[i].value;
// expected-warning@-1 {{'i' is the index into 'rates' here, but on this path the loop has run to its end, which leaves 'i' at 4, the number of elements (experimental check 'index-past-end')}}
}

// --- and where the code knows.

int search_tested(int id) {
  int i;

  for (i = 0; i < ARRAY_SIZE(rates); i++)
    if (rates[i].id == id)
      break;
  if (i == ARRAY_SIZE(rates))
    return -EINVAL;
  return rates[i].value;
}

int search_flag(int id) {
  bool found = false;
  int i;

  for (i = 0; i < ARRAY_SIZE(rates); i++) {
    if (rates[i].id == id) {
      found = true;
      break;
    }
  }
  if (!found)
    return -EINVAL;
  return rates[i].value;
}

int search_pointer(int id) {
  const struct rate *r = NULL;
  int i;

  for (i = 0; i < ARRAY_SIZE(rates); i++) {
    if (rates[i].id == id) {
      r = &rates[i];
      break;
    }
  }
  if (!r)
    return -EINVAL;
  return rates[i].value;
}

int search_goto(int id) {
  int i;

  for (i = 0; i < ARRAY_SIZE(rates); i++)
    if (rates[i].id == id)
      goto found;
  return -EINVAL;
found:
  return rates[i].value;
}

int search_return(int id) {
  int i;

  for (i = 0; i < ARRAY_SIZE(rates); i++)
    if (rates[i].id == id)
      return rates[i].value;
  return -EINVAL;
}

// The last element is the answer if no other is.
int search_default(int id) {
  int i;

  for (i = 0; i < ARRAY_SIZE(rates) - 1; i++)
    if (rates[i].id == id)
      break;
  return rates[i].value;
}

int search_clamped(int id) {
  int i;

  for (i = 0; i < ARRAY_SIZE(rates); i++)
    if (rates[i].id == id)
      break;
  if (i >= ARRAY_SIZE(rates))
    i = 0;
  return rates[i].value;
}

int search_stepped_back(int id) {
  int i;

  for (i = 0; i < ARRAY_SIZE(rates); i++)
    if (rates[i].id > id)
      break;
  i--;
  return rates[i].value;
}

// One element more than the loop counts.
static int wide[ARRAY_SIZE(rates) + 1];

int search_wide(int id) {
  int i;

  for (i = 0; i < ARRAY_SIZE(rates); i++)
    if (rates[i].id == id)
      break;
  return wide[i];
}

int search_again(int id) {
  int i;

  for (i = 0; i < ARRAY_SIZE(rates); i++)
    if (rates[i].id == id)
      break;
  for (i = 0; i < ARRAY_SIZE(rates); i++)
    note(rates[i].value);
  return 0;
}

// The index is tested where it is stepped, and comes back to the test of
// the loop below the bound.
int climb(int *slots) {
  int levels[8];
  int level = 1;

  levels[0] = 0;
  while (level < 8) {
    if (slots[level]) {
      level++;
      if (level == 8)
        return 1;
      continue;
    }
    break;
  }
  levels[level] = 1;
  return levels[0];
}

// The same without the test: the index can be the bound.
int climb_untested(int *slots) {
  int levels[8];
  int level = 1;

  levels[0] = 0;
  while (level < 8) { // expected-note {{the loop ends here if nothing has left it before}}
    if (slots[level]) {
      level++;
      continue;
    }
    break;
  }
  levels[level] = 1;
// expected-warning@-1 {{'level' is the index into 'levels' here, but on this path the loop has run to its end, which leaves 'level' at 8, the number of elements (experimental check 'index-past-end')}}
  return levels[0];
}

// The test is part of a condition whose value is used as a whole.
int get_checked(unsigned int i) {
  if (unlikely(i >= ARRAY_SIZE(rates) || !rates[i].id))
    return -EINVAL;
  return rates[i].value;
}

// The loop goes on while the index is in range: its body is not behind
// the test that fails.
int collect(void) {
  int vals[4];
  int i = 0, v;

  do {
    v = get();
    if (v > 0) {
      vals[i] = v;
      i++;
    }
  } while (v && i < 4 && v != 7);
  return vals[0];
}

// The test guards one use.  What comes behind the "if" is not what it is
// about.
static int pairs[ARRAY_SIZE(rates) * 2];

int guarded_use(unsigned int i, unsigned int j) {
  if (i < ARRAY_SIZE(rates) && j < 2)
    note(pairs[i * 2 + j]);
  return rates[i].value;
}

// The value of the test is kept, as WARN_ON() does.
int kept_value(unsigned int i) {
  int bad = !!(i >= ARRAY_SIZE(rates));

  if (unlikely(bad))
    return -EINVAL;
  return rates[i].value;
}

// The address of the element behind the last one is a pointer like others.
const struct rate *end_of_rates(void) {
  int i;

  for (i = 0; i < ARRAY_SIZE(rates); i++)
    note(rates[i].id);
  return &rates[i];
}

// ---------------------------------------------------------------------------
// The cursor of a list.

int lookup(struct list_head *head, int id) {
  struct item *pos;

  list_for_each_entry(pos, head, list) // expected-note {{the loop ends here if nothing has left it before}}
    if (pos->id == id)
      break;
  return pos->value;
// expected-warning@-1 {{'pos' is dereferenced here, but on this path the loop over the list has run to its end, which leaves 'pos' at the head of the list, taken for an entry (experimental check 'cursor-past-end')}}
}

int lookup_rcu(struct list_head *head, int id) {
  struct item *pos;

  list_for_each_entry_rcu(pos, head, list) // expected-note {{the loop ends here if nothing has left it before}}
    if (pos->id == id)
      break;
  pos->value = 0;
// expected-warning@-1 {{'pos' is dereferenced here, but on this path the loop over the list has run to its end, which leaves 'pos' at the head of the list, taken for an entry (experimental check 'cursor-past-end')}}
  return 0;
}

int lookup_passed(struct list_head *head, int id) {
  struct item *pos;

  list_for_each_entry(pos, head, list) // expected-note {{the loop ends here if nothing has left it before}}
    if (pos->id == id)
      break;
  return item_value(pos);
// expected-warning@-1 {{'pos' is passed to 'item_value', which dereferences it, but on this path the loop over the list has run to its end, which leaves 'pos' at the head of the list, taken for an entry (experimental check 'cursor-past-end')}}
}

// An empty list ends the loop before its first pass.
int first_set(struct list_head *head) {
  struct item *pos;

  list_for_each_entry(pos, head, list) // expected-note {{the loop ends here if nothing has left it before}}
    if (pos->id)
      break;
  return pos->value;
// expected-warning@-1 {{'pos' is dereferenced here, but on this path the loop over the list has run to its end, which leaves 'pos' at the head of the list, taken for an entry (experimental check 'cursor-past-end')}}
}

// --- and where the code knows.

int lookup_tested(struct list_head *head, int id) {
  struct item *pos;

  list_for_each_entry(pos, head, list)
    if (pos->id == id)
      break;
  if (list_entry_is_head(pos, head, list))
    return -ENOENT;
  return pos->value;
}

int lookup_tested_open(struct list_head *head, int id) {
  struct item *pos;

  list_for_each_entry(pos, head, list)
    if (pos->id == id)
      break;
  if (&pos->list == head)
    return -ENOENT;
  return pos->value;
}

int lookup_flag(struct list_head *head, int id) {
  struct item *pos;
  int ret = -ENOENT;

  list_for_each_entry(pos, head, list) {
    if (pos->id == id) {
      ret = 0;
      break;
    }
  }
  if (ret)
    return ret;
  return pos->value;
}

int lookup_goto(struct list_head *head, int id) {
  struct item *pos;

  list_for_each_entry(pos, head, list)
    if (pos->id == id)
      goto found;
  return -ENOENT;
found:
  return pos->value;
}

int lookup_copy(struct list_head *head, int id) {
  struct item *pos, *found = NULL;

  list_for_each_entry(pos, head, list) {
    if (pos->id == id) {
      found = pos;
      break;
    }
  }
  if (!found)
    return -ENOENT;
  return pos->value;
}

// The new item goes in front of the first larger one, or to the end: the
// head is where the list ends.
void insert_sorted(struct list_head *head, struct item *it) {
  struct item *pos;

  list_for_each_entry(pos, head, list)
    if (pos->id > it->id)
      break;
  list_add(&it->list, &pos->list);
}

// Going on from the head is the first entry again.
int twice(struct list_head *head, int id) {
  struct item *pos;

  list_for_each_entry(pos, head, list)
    if (pos->id == id)
      break;
  list_for_each_entry_continue(pos, head, list)
    note(pos->value);
  return 0;
}

// The loop takes its entries off the list.  If it runs to its end, the
// list is empty.
bool list_empty(const struct list_head *head);
void list_del(struct list_head *entry);

int drain(struct list_head *head) {
  struct item *pos;

  list_for_each_entry(pos, head, list) {
    if (!pos->id)
      break;
    list_del(&pos->list);
  }
  if (!list_empty(head) && pos->value)
    return 1;
  return 0;
}

// The loop walks to the entry with a number, and does not look at it.
int nth(struct list_head *head, int n) {
  struct item *pos;

  list_for_each_entry(pos, head, list) {
    if (n == 0)
      break;
    n--;
  }
  return pos->value;
}

// The array is another one behind the test.
struct bag *grow(struct bag *b);

int append(struct bag *b, int count, int id) {
  if (count >= b->count)
    b = grow(b);
  b->slots[count] = id;
  return 0;
}

// The two tests ask the same question.
int search_status(int id) {
  int i, status = 0;

  for (i = 0; i < ARRAY_SIZE(rates); i++) {
    status = get();
    if (status == 5)
      break;
  }
  if (status != 5)
    return -ENOENT;
  return rates[i].value;
}

// A ring of items: the head of the list is in an item itself.
int ring(struct item *first, int id) {
  struct item *pos;

  list_for_each_entry(pos, &first->list, list)
    if (pos->id == id)
      break;
  return pos->value;
}

// The item that was found is kept in another variable, which is not NULL
// then.
int lookup_kept(struct list_head *head, int id) {
  struct item *pos, *found = NULL;
  int old = 0;

  list_for_each_entry(pos, head, list) {
    if (pos->id == id) {
      old = pos->value;
      found = pos;
    }
    if (found)
      break;
  }
  if (old)
    return pos->value;
  return 0;
}

// What the function does with the item is not known.
void lookup_handed_on(struct list_head *head, int id) {
  struct item *pos;

  list_for_each_entry(pos, head, list)
    if (pos->id == id)
      break;
  item_put(pos);
}

// The variable is the owner of the list here, not an entry of it.
int walk_children(struct item *parent, int id) {
  struct list_head *p;
  int n = 0;

  for (p = parent->children.next; p != &parent->children; p = p->next)
    n++;
  return n + parent->value;
}

int walk_down(struct item *parent) {
  struct list_head *next = parent->children.next;
  int n = 0;

  while (next != &parent->children) {
    struct item *child = list_entry(next, struct item, list);

    next = next->next;
    if (child->id) {
      parent = child;
      next = parent->children.next;
    }
    n++;
  }
  return n + parent->value;
}
