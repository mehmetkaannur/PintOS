#include <debug.h>
#include "vm/page.h"
#include "vm/frame.h"
#include "threads/malloc.h"

/* Hash function for supplemental page table entry. */
unsigned
hash_spte (const struct hash_elem *e, void *aux UNUSED)
{
  const struct spt_entry *spte = hash_entry (e, struct spt_entry, elem);
  return hash_bytes (&spte->user_page, sizeof spte->user_page);
}

/* Less function for supplemental page table entry. */
bool
less_spte (const struct hash_elem *a, const struct hash_elem *b,
           void *aux UNUSED)
{
  const struct spt_entry *sa = hash_entry (a, struct spt_entry, elem);
  const struct spt_entry *sb = hash_entry (b, struct spt_entry, elem);
  return sa->user_page < sb->user_page;
}

/* Function to free page in supplemental page table entry. */
void
destroy_spte (struct hash_elem *e, void *aux UNUSED)
{
  struct spt_entry *spte = hash_entry (e, struct spt_entry, elem);

  /* Remove page from swap space. */
  if (spte->state == SWAPPED)
    {
      PANIC ("Not implemented.");
    }

  free (spte);
}
