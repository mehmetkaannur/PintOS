#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>
#include "filesys/off_t.h"
#include "threads/thread.h"

/* Possible types of page, recorded in SPT. */
enum page_type
  {
    STACK,             /* Stack page, written to swap space on eviction. */
    MMAP_FILE,         /* A page from a memory mapped file, written back 
                          to the file system on eviction. */
    EXEC_FILE,         /* Page from an executable file, written to the swap
                          space on eviction. */
  };

/* Supplemental page table (SPT) entry. */
struct spt_entry
  {
    /* The following fields remain constant after being initialised for
       lazy loading or as stack pages. */
    struct hash_elem elem;        /* Hash element for thread's
                                     supplemental page table. */
    uint8_t *user_page;           /* User virtual page. */
    enum page_type page_type;     /* Type of page wrt. eviction. */
    struct file *file;            /* Pointer to file for page. */
    uint32_t file_ofs;            /* Offset in file to read data from. */
    uint32_t page_read_bytes;     /* Number of bytes to read from file. */
    uint32_t page_zero_bytes;     /* Number of bytes to zero in page. */
    bool writable;                /* Indicates if page is writable. (Note
                                     this field may be updated during the
                                     lazy loading spt setup but not after). */

    /* The following fields may change after initialisation. */
    bool in_memory;               /* Indicates if page is in memory. */
    bool in_swap;                 /* Indicates if page is in swap space. */
    void *kpage;                  /* Kernel virtual page if in memory. */
    size_t swap_slot;             /* Swap slot if in swap space. */
  };

hash_hash_func hash_spte;
hash_less_func less_spte;
hash_action_func destroy_spte;
struct spt_entry *get_spt_entry (void *upage, struct thread *t);

#endif /* vm/page.h */
