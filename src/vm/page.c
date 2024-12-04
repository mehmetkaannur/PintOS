#include <debug.h>
#include <stdio.h>
#include "vm/page.h"
#include "vm/frame.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include "filesys/file.h"
#include "devices/swap.h"
#include "vm/shared_page.h"

/* Hash function for supplemental page table entry. */
unsigned
hash_spte (const struct hash_elem *e, void *aux UNUSED)
{
  const struct spt_entry *spte = hash_entry (e, struct spt_entry, elem);
  return hash_ptr (spte->user_page);
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

/* Function to free resources related to an spt entry from the current
   thread's spt. */
void
destroy_spte (struct hash_elem *e, void *aux UNUSED)
{
  struct spt_entry *spte = hash_entry (e, struct spt_entry, elem);

  if (spte->in_memory)
    {
      /* Write page back to file system, if dirty. */ 
      if ((spte->page_type == MMAP_FILE)
          && pagedir_is_dirty (thread_current ()->pagedir, spte->user_page))
        {
          lock_acquire (&filesys_lock);
          file_write_at (spte->file, spte->user_page, spte->page_read_bytes,
                         spte->file_ofs);
          lock_release (&filesys_lock);
        }

      if ((spte->page_type == EXEC_FILE && !spte->writable)
          || spte->page_type == MMAP_FILE)
        {
          /* Remove page from shared pages hash map. */
          shared_pages_remove (spte->file, spte->file_ofs);
        }

    }
  else if (spte->in_swap)
    {
      /* Remove page from swap space. */
      swap_drop (spte->swap_slot);
    }

  free (spte);
}

/* Returns the spt entry for the page with user address UPAGE
   in the spt of thread T. */
struct spt_entry *
get_spt_entry (void *upage, struct thread *t)
{
  struct spt_entry temp_spte;
  temp_spte.user_page = pg_round_down (upage);
  struct hash_elem *e = hash_find (&t->supp_page_table, &temp_spte.elem);

  return e == NULL ? NULL : hash_entry (e, struct spt_entry, elem);
}
