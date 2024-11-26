#include <debug.h>
#include <stdio.h>
#include "vm/page.h"
#include "vm/frame.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include "filesys/file.h"

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

/* Function to free page in supplemental page table entry. */
void
destroy_spte (struct hash_elem *e, void *aux UNUSED)
{
  struct spt_entry *spte = hash_entry (e, struct spt_entry, elem);

  if (spte->in_memory)
    {
      /* Write page back to file system, if dirty. */ 
      if (spte->evict_to == FILE_SYSTEM
          && pagedir_is_dirty (thread_current ()->pagedir, spte->user_page))
        {
          lock_acquire (&filesys_lock);
          file_write_at (spte->file, spte->user_page, spte->page_read_bytes,
                         spte->file_ofs);
          lock_release (&filesys_lock);
        }

      free_frame (spte->kpage);
    }
  else if (spte->evict_to == SWAP_SPACE)
    {
      /* Remove page from swap space. */
      PANIC ("Not implemented.");
    }

  free (spte);
}
