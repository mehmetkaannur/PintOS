#include <debug.h>
#include "vm/page.h"
#include "filesys/file.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "userprog/syscall.h"

unsigned
hash_spt (const struct hash_elem *e, void *aux UNUSED)
{
  const struct spt_entry *spte = hash_entry (e, struct spt_entry, elem);
  return hash_bytes (&spte->user_page, sizeof spte->user_page);
}

bool
less_spt (const struct hash_elem *a, const struct hash_elem *b,
          void *aux UNUSED)
{
  const struct spt_entry *sa = hash_entry (a, struct spt_entry, elem);
  const struct spt_entry *sb = hash_entry (b, struct spt_entry, elem);
  return sa->user_page < sb->user_page;
}

struct spt_entry *
get_page_from_spt (void *upage)
{
  struct spt_entry temp_spte;
  temp_spte.user_page = pg_round_down (upage);
  struct hash_elem *e = hash_find (&thread_current ()->supp_page_table, &temp_spte.elem);
  if (e != NULL) 
    {
      return hash_entry(e, struct spt_entry, elem);
    }
  return NULL;
}

void
remove_page_from_spt (void *upage)
{
  struct spt_entry temp_spte;
  temp_spte.user_page = upage;
  struct hash_elem *e = hash_delete (&thread_current ()->supp_page_table, &temp_spte.elem);
  if (e != NULL) 
    {
      struct spt_entry *spte = hash_entry (e, struct spt_entry, elem);
      free (spte);
    }
}
