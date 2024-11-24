#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <hash.h>
#include "threads/palloc.h"

/* Entry for frame table. */
struct frame_table_entry
  {
    void *frame;                    /* Kernel virtual address for frame. */
    struct thread *owner;           /* Pointer to thread which owns frame. */
    struct hash_elem hash_elem;     /* Hash element. */
    struct list page_table_entries; /* List of page table entries 
                                       referring to frame. */
  };

void frame_table_init (void);

extern struct hash frame_table;
extern struct lock frame_table_lock;

void *get_frame (enum palloc_flags flags);
void free_frame (void *frame);

#endif /* vm/frame.h */
