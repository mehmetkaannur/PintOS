#include <debug.h>
#include "vm/frame.h"
#include "threads/synch.h"

/* Frame table hash map. */
struct hash frame_table;

/* Lock for frame table. */
struct lock frame_table_lock;

static hash_hash_func hash_frame_table_entry;
static hash_less_func less_frame_table_entry;

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
