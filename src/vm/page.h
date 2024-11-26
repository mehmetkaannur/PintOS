#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>
#include "filesys/off_t.h"

/* Possible states of a page not in memory, recorded in SPT. */
enum evict_location
  {
    SWAP_SPACE,                   /* Page is in swap space. */
    FILE_SYSTEM,                  /* Page is in file system. */
    MMAP_FILE                     /* Page is part of a memory-mapped file. */
  };

/* Supplemental page table (SPT) entry. */
struct spt_entry
  {
    struct hash_elem elem;        /* Hash element for thread's
                                     supplemental page table. */
    bool in_memory;               /* Indicates if page is in memory. */
    uint8_t *user_page;           /* User virtual page. */
    enum evict_location evict_to; /* Where the page should be if evicted. */
    bool writable;                /* Indicates if page is writable. */
    struct file *file;            /* Pointer to file for page. */
    uint32_t file_ofs;            /* Offset in file to read data from. */
    uint32_t page_read_bytes;     /* Number of bytes to read from file. */
    uint32_t page_zero_bytes;     /* Number of bytes to zero in page. */
    struct mmap_file *mmap_file;  /* Pointer to the mmap_file structure. */

    bool loaded;                  /* True if the page is loaded into memory. */
    void *kpage;                  /* Kernel virtual page if in memory. */
  };

hash_hash_func hash_spte;
hash_less_func less_spte;
hash_action_func destroy_spte;
struct spt_entry * get_page_from_spt (void *upage);
void remove_page_from_spt (void *upage);

#endif /* vm/page.h */
