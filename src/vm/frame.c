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
  bool shared = false;

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
      
      lock_acquire (&f->frame_lock);

      shared = list_size (&f->frame_references) > 1;
        
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
        
        lock_acquire (&fr->owner->spt_lock);
        if (get_spt_entry (fr->upage, fr->owner)->is_pinned)
          {
            /* Page is pinned, don't evict. */
            accessed = true;
            lock_release (&fr->owner->spt_lock);
            break;
          }
        else if (pagedir_is_accessed (fr->pd, fr->upage))
          {
            /* Give frame a second chance. */
            accessed = true;
            pagedir_set_accessed (fr->pd, fr->upage, false);
          }
        lock_release (&fr->owner->spt_lock);
      }

      if (!accessed)
        {
          /* Evict this frame. */
          frame = f->frame;
          break;
        }

      lock_release (&f->frame_lock);
    }

  if (shared)
    {
      /* Remove shared page from shared pages hash map. */
      struct list_elem *el = list_begin (&f->frame_references);
      struct frame_reference *fr = list_entry (el,
                                               struct frame_reference,
                                               elem);
      lock_acquire (&fr->owner->spt_lock);
      struct spt_entry *spte = get_spt_entry (fr->upage, fr->owner);
      shared_pages_remove (spte->file, spte->file_ofs);
      lock_release (&fr->owner->spt_lock);
    }

  lock_release (&shared_pages_lock);

  /* Remove entry for frame from frame table so it does not get chosen 
     for eviction by another thread. */
  hash_delete (&frame_table, &f->hash_elem);

  lock_release (&frame_table_lock);

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

  lock_release (&f->frame_lock);

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

/* Free frame containing user page with kernel virtual address KPAGE. */
void
free_frame (void *kpage)
{
  struct frame_table_entry i;
  i.frame = kpage;

  /* Find relevant frame table entry from frame table. */
  lock_acquire (&frame_table_lock);
  struct hash_elem *e = hash_find (&frame_table, &i.hash_elem);

  /* If frame entry cannot be found in frame table, another thread has chosen
     to evict the frame and will free it. */
  if (e == NULL)
    {
      lock_release (&frame_table_lock);
      return;
    }
  
  struct frame_table_entry *fte = hash_entry (e, struct frame_table_entry,
                                              hash_elem);

  /* Remove frame table entry, to prevent frame being chosen for eviction. */
  hash_delete (&frame_table, e);

  lock_release (&frame_table_lock);

  struct thread *t = thread_current ();
  struct list_elem *el = list_begin (&fte->frame_references);

  /* Remove all references to this frame. */
  lock_acquire (&fte->frame_lock);
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
  lock_release (&fte->frame_lock);

  /* If page is shared don't free frame. */
  if (shared)
    {
      /* Put frame table entry back into frame table. */
      lock_acquire (&frame_table_lock);
      hash_insert (&frame_table, &fte->hash_elem);
      lock_release (&frame_table_lock);

      return;
    }

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
