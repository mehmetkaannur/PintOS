#include <hash.h>

/* Possible states of a page not in memory, recorded in SPT. */
enum page_state
  {
    SWAPPED,                      /* Page is swapped out. */
    FILE_SYSTEM,                  /* Page is in file system. */
    ZERO,                         /* Page is to be zeroed. */
  };

/* Supplemental page table entry (SPT). */
struct spt_entry
  {
    struct hash_elem elem;        /* Hash element for thread's
                                     supplemental page table. */
    void *user_page;              /* User virtual page. */
    enum page_state state;        /* State of the page. */
    bool writable;                /* Indicates if page is writable. */
  };

hash_hash_func hash_spt;
hash_less_func less_spt;
