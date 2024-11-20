#include <hash.h>

/* Entry for frame table. */
struct frame_table_entry
  {
    void *frame;                 /* Frame address. */
    void *user_page;             /* User virtual address for page. */
    struct thread *thread;       /* Pointer to thread which owns frame. */
    struct hash_elem hash_elem;  /* Hash element. */
  };

void frame_table_init (void);

extern struct hash frame_table;
