#include <debug.h>
#include "vm/page.h"

unsigned
hash_spt (const struct hash_elem *e, void *aux UNUSED)
{
  const struct spt_entry *spte = hash_entry (e, struct spt_entry, elem);
  return hash_ptr (&spte->user_page);
}

bool
less_spt (const struct hash_elem *a, const struct hash_elem *b,
          void *aux UNUSED)
{
  const struct spt_entry *sa = hash_entry (a, struct spt_entry, elem);
  const struct spt_entry *sb = hash_entry (b, struct spt_entry, elem);
  return sa->user_page < sb->user_page;
}
