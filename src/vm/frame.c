#include <debug.h>
#include <bitmap.h>
#include "vm/page.h"
#include "vm/frame.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include "devices/swap.h"

/* Frame table hash map. */
struct hash frame_table;

/* Lock for frame table. */
struct lock frame_table_lock;

static hash_hash_func hash_frame_table_entry;
static hash_less_func less_frame_table_entry;

static void *evict_frame (void);

/* Evict a frame using the 'second-chance' page replacement algorithm. */
static void *
evict_frame (void)
{
  ASSERT (!hash_empty (&frame_table));

  void *frame = NULL;

  lock_acquire (&frame_table_lock);

  /* Iterate frame table entries to find a frame to evict. */
  struct hash_iterator i;
  struct frame_table_entry *f;
  hash_first (&i, &frame_table);
  while (frame == NULL)
  {
    if (hash_next (&i) == NULL)
      {
        /* Reached end of frame table, start again. */
        hash_first (&i, &frame_table);
        hash_next (&i);
      }

    f = hash_entry (hash_cur (&i), struct frame_table_entry, hash_elem);
    
    /* Iterate frame references to see if frame was accessed by any page
       referring to it. */
    bool accessed = false;
    struct list_elem *el; 
    for (el = list_begin (&f->frame_references);
         el != list_end (&f->frame_references);
         el = list_next (el))
    {
      struct frame_reference *fr = list_entry (el, struct frame_reference,
                                               elem);
      if (pagedir_is_accessed (fr->pd, fr->upage))
        {
          /* Give frame a second chance. */
          accessed = true;
          pagedir_set_accessed (fr->pd, fr->upage, false);
        }
    }
    
    if (!accessed)
      {
        /* Evict this frame. */
        frame = f->frame;
        break;
      }
  }
  
  lock_release (&frame_table_lock);

  if (!list_empty (&f->frame_references))
    {
      /* Write frame back based on spt entry. */
      struct list_elem *el = list_front (&f->frame_references); 
      struct frame_reference *fr = list_entry (el, struct frame_reference,
                                               elem);
      struct spt_entry *spte = get_page_from_spt (fr->upage);

      /* Write back to file_system. */
      if (spte->evict_to == FILE_SYSTEM)
        {
          if (pagedir_is_dirty (fr->pd, fr->upage))
            {
              /* Write page back to file system. */
              lock_acquire (&filesys_lock);
              file_write_at (spte->file, spte->user_page,
                             spte->page_read_bytes, spte->file_ofs);
              lock_release (&filesys_lock);
            }

          spte->in_memory = false;
        }
      /* Write back to swap space. */
      else if (spte->evict_to == SWAP_SPACE)
        {
          /* Swap page to swap space. */
          size_t swap_slot = swap_out (spte->user_page);
          if (swap_slot == BITMAP_ERROR)
            {
              PANIC ("Failed to swap out page.");
            }

          spte->swap_slot = swap_slot;
          spte->in_memory = false;
        }
    }

  /* Free frame being evicted,, writing back page if necessary. */
  free_frame (frame);

  return frame;
}

/* Get a single free frame for user page.
   Returns the kernel virtual address of this frame. */
void *
get_frame (enum palloc_flags flags)
{
  void *kpage = palloc_get_page (flags);
  
  if (kpage == NULL)
    {
      /* Evict a frame. */
      kpage = evict_frame ();
    }
  
  struct frame_table_entry *fte = malloc (sizeof (struct frame_table_entry));
  if (fte == NULL)
    {
      return NULL;
    }

  /* Set up frame table entry. */
  fte->frame = kpage;
  list_init (&fte->frame_references);
  
  /* Insert frame table entry into table. 
     (frame_table_lock will be released by install_page). */
  lock_acquire (&frame_table_lock);
  hash_insert (&frame_table, &fte->hash_elem);
  lock_release (&frame_table_lock);

  return kpage;
}

/* Free frame containing user page with kernel virtual address KPAGE. */
void
free_frame (void *kpage)
{
  palloc_free_page (kpage);

  struct frame_table_entry i;
  i.frame = kpage;

  lock_acquire (&frame_table_lock);

  /* Find relevant frame table entry. */
  struct hash_elem *e = hash_find (&frame_table, &i.hash_elem);
  struct frame_table_entry *fte = hash_entry (e, struct frame_table_entry,
                                              hash_elem);

  /* Remove all references to this frame. */
  struct list_elem *el = list_begin (&fte->frame_references);
  while (el != list_end (&fte->frame_references))
    {
      struct frame_reference *fr = list_entry (el, struct frame_reference,
                                               elem);
      pagedir_clear_page (fr->pd, fr->upage);
      el = list_remove (el);
      free (fr);
    }

  /* Remove frame table entry from frame table. */
  hash_delete (&frame_table, &fte->hash_elem);
  free (fte);

  lock_release (&frame_table_lock);
}

/* Hash function for frame table. */
static unsigned
hash_frame_table_entry (const struct hash_elem *e, void *aux UNUSED)
{
  const struct frame_table_entry *fte = hash_entry (e,
                                                    struct frame_table_entry,
                                                    hash_elem);

  return hash_ptr (fte->frame);
}

/* Less function for frame table. */
static bool
less_frame_table_entry (const struct hash_elem *a,
                        const struct hash_elem *b,
                        void *aux UNUSED)
{
  const struct frame_table_entry *fte_a = hash_entry (a,
                                                      struct frame_table_entry,
                                                      hash_elem);
  const struct frame_table_entry *fte_b = hash_entry (b,
                                                      struct frame_table_entry,
                                                      hash_elem);

  return fte_a->frame < fte_b->frame;
}

void
frame_table_init (void)
{
  bool success = hash_init (&frame_table, hash_frame_table_entry,
                            less_frame_table_entry, NULL);

  if (!success)
    {
      PANIC ("Failed to initialise frame table hash map.");
    }

  lock_init (&frame_table_lock);
}
