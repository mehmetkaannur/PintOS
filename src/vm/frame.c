#include <debug.h>
#include "vm/frame.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include "userprog/pagedir.h"

/* Frame table hash map. */
struct hash frame_table;

/* Lock for frame table. */
struct lock frame_table_lock;

static hash_hash_func hash_frame_table_entry;
static hash_less_func less_frame_table_entry;

/* Get frame for user page. */
void *
get_frame (enum palloc_flags flags)
{
  void *page = palloc_get_page (flags);
  
  struct frame_table_entry *fte = malloc (sizeof (struct frame_table_entry));
  if (fte == NULL)
    {
      return NULL;
    }

  /* Set up frame table entry. */
  fte->frame = page;
  fte->owner = thread_current ();
  list_init (&fte->page_table_entries);
  
  /* Insert frame table entry into table. 
     (frame_table_lock will be released by install_page). */
  lock_acquire (&frame_table_lock);
  hash_insert (&frame_table, &fte->hash_elem);
  lock_release (&frame_table_lock);

  return page;
}

/* Free frame for user page. */
void
free_frame (void *page)
{
  palloc_free_page (page);

  struct frame_table_entry i;
  i.frame = pagedir_get_page (thread_current ()->pagedir, page);

  lock_acquire (&frame_table_lock);

  /* Find relevant frame table entry. */
  struct hash_elem *e = hash_find (&frame_table, &i.hash_elem);
  struct frame_table_entry *fte = hash_entry (e, struct frame_table_entry,
                                              hash_elem);

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

  return hash_ptr (&fte->frame);
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
