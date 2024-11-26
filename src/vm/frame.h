#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <hash.h>
#include "threads/palloc.h"

struct frame_reference
  {
    uint32_t *pd;             /* Page directory of thread which has
                                 reference to frame. */
    void *upage;              /* User virtual address of page in frame. */
    struct list_elem elem;    /* List element for frame table entry. */
  };

/* Entry for frame table. */
struct frame_table_entry
  {
    void *frame;                    /* Kernel virtual address for frame. */
    struct list frame_references;   /* List of references to frame. */
    struct hash_elem hash_elem;     /* Hash element. */
  };

void frame_table_init (void);

extern struct hash frame_table;
extern struct lock frame_table_lock;

void *get_frame (enum palloc_flags flags);
void free_frame (void *frame);

#endif /* vm/frame.h */
