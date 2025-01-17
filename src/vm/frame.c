#include <debug.h>
#include <bitmap.h>
#include <stdio.h>
#include "vm/page.h"
#include "vm/frame.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include "devices/swap.h"
#include "vm/shared_page.h"

/* Frame table hash map. */
struct hash frame_table;

/* Lock for frame table. */
struct lock frame_table_lock;

static hash_hash_func hash_frame_table_entry;
static hash_less_func less_frame_table_entry;

static list_less_func frame_reference_less;

static void *evict_frame (void);

/* Comparator for frame reference list. */
static bool
frame_reference_less (const struct list_elem *a, const struct list_elem *b,
                      void *aux UNUSED)
{
  struct frame_reference *fa = list_entry (a, struct frame_reference, elem);
  struct frame_reference *fb = list_entry (b, struct frame_reference, elem);

  return fa->owner->tid < fb->owner->tid;
}

/* Evict a frame using the 'second-chance' page replacement algorithm. */
static void *
evict_frame (void)
{
  ASSERT (!hash_empty (&frame_table));

  void *frame = NULL;
  bool shareable = false;

  lock_acquire (&shared_pages_lock);
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
      
      /* Check if frame is shareable. */
      struct list_elem *el = list_begin (&f->frame_references);
      struct frame_reference *fr = list_entry (el,
                                               struct frame_reference,
                                               elem);
      lock_acquire (&fr->owner->spt_lock);
      struct spt_entry *spte = get_spt_entry (fr->upage, fr->owner);
      lock_release (&fr->owner->spt_lock);

      shareable = is_shareable (spte);

      /* Iterate frame references to see if frame was accessed by any page
         referring to it. */
      bool accessed = false;
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

  if (shareable)
    {
      /* Remove shareable page from shared pages hash map. */
      struct list_elem *el = list_begin (&f->frame_references);
      struct frame_reference *fr = list_entry (el,
                                               struct frame_reference,
                                               elem);
      lock_acquire (&fr->owner->spt_lock);
      struct spt_entry *spte = get_spt_entry (fr->upage, fr->owner);
      lock_release (&fr->owner->spt_lock);

      shared_pages_remove (spte->file, spte->file_ofs);
    }

  lock_release (&shared_pages_lock);

  /* Remove entry for frame from frame table so it does not get chosen 
     for eviction by another thread. */
  hash_delete (&frame_table, &f->hash_elem);

  /* Sort frame references to ensure lock ordering. */
  list_sort (&f->frame_references, frame_reference_less, NULL);

  /* Clear all references to this frame. */
  struct list_elem *e;
  for (e = list_begin (&f->frame_references);
       e != list_end (&f->frame_references);
       e = list_next (e))
    {
      struct frame_reference *fr = list_entry (e, struct frame_reference,
                                               elem);
      lock_acquire (&fr->owner->io_lock);
      pagedir_clear_page (fr->pd, fr->upage);
    }

  lock_release (&frame_table_lock);

  size_t swap_slot;
  bool swapped = false;

  /* Every frame recorded in the frame table contains a user page. */
  ASSERT (!list_empty (&f->frame_references));
  
  /* Write frame back based on spt entry. */
  struct list_elem *el = list_front (&f->frame_references); 
  struct frame_reference *fr = list_entry (el, struct frame_reference,
                                           elem);
  lock_acquire (&fr->owner->spt_lock);
  struct spt_entry *spte = get_spt_entry (fr->upage, fr->owner);
  lock_release (&fr->owner->spt_lock);

  /* Write back if dirty. */
  if (pagedir_is_dirty (fr->pd, fr->upage))
    {
      if (spte->page_type == MMAP_FILE)
        {
          lock_acquire (&filesys_lock);

          /* Write page back to file system. */
          file_seek (spte->file, spte->file_ofs);
          if (file_write (spte->file, frame, spte->page_read_bytes)
              != (off_t) spte->page_read_bytes)
            {
              PANIC ("Failed to write page back to file system.");
            }

          lock_release (&filesys_lock);
        }
      else
        {
          /* Swap page to swap space. */
          swap_slot = swap_out (frame);
          if (swap_slot == BITMAP_ERROR)
            {
              PANIC ("Failed to swap out page.");
            }
          swapped = true;
        }
    }

  /* Update spt entries for all references to frame. */
  e = list_begin (&f->frame_references);
  while (e != list_end (&f->frame_references))
    {
      struct frame_reference *fr = list_entry (e,
                                               struct frame_reference,
                                               elem);
      lock_acquire (&fr->owner->spt_lock);
      struct spt_entry *spte = get_spt_entry (fr->upage, fr->owner);
      lock_release (&fr->owner->spt_lock);

      if (swapped)
        {
          spte->swap_slot = swap_slot;
          spte->in_swap = true;
        }

      spte->in_memory = false;
      lock_release (&fr->owner->io_lock);

      e = list_remove (e);
      free (fr);
    }

  free (f);

  /* Free frame being evicted. */
  palloc_free_page (frame);

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
      evict_frame ();
      kpage = palloc_get_page (flags);
    }
  
  ASSERT (kpage != NULL);

  return kpage;
}

/* Free frame containing user page with kernel virtual address KPAGE,
   Must hold frame_table_lock on entry to this function. */
void
free_frame (void *kpage)
{
  struct frame_table_entry i;
  i.frame = kpage;

  /* Find relevant frame table entry from frame table. */
  struct hash_elem *e = hash_find (&frame_table, &i.hash_elem);
  struct frame_table_entry *fte = hash_entry (e, struct frame_table_entry,
                                              hash_elem);

  struct thread *t = thread_current ();
  struct list_elem *el = list_begin (&fte->frame_references);

  /* Remove all references to this frame. */
  bool shared = false;
  while (el != list_end (&fte->frame_references))
    {
      struct frame_reference *fr = list_entry (el, struct frame_reference,
                                               elem);
      if (fr->owner != t)
        {
          shared = true;
          el = list_next (el);
        }
      else
        {
          pagedir_clear_page (fr->pd, fr->upage);
          el = list_remove (el);
          free (fr);
        }
    }

  /* If page is shared don't free frame. */
  if (shared)
    {
      return;
    }

  /* Remove frame table entry. */
  hash_delete (&frame_table, e);

  /* Free frame. */  
  palloc_free_page (kpage);
  free (fte);
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
