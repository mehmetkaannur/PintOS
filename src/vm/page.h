#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>
#include "filesys/off_t.h"
#include "threads/thread.h"

/* Possible types of page, recorded in SPT. */
enum page_type
  {
    STACK,             /* Stack page, written to swap space on eviction. */
    FILE,              /* File-backed page (e.g. from a memory mapped file),
                          written back to file system on eviction. */
    READ_ONLY_FILE,    /* Page from a read-only file (e.g. executable
                          data page), written to swap space on eviction. */
  };

/* Supplemental page table (SPT) entry. */
struct spt_entry
  {
    struct hash_elem elem;        /* Hash element for thread's
                                     supplemental page table. */
    bool in_memory;               /* Indicates if page is in memory. */
    bool in_swap;                 /* Indicates if page is in swap space. */
    uint8_t *user_page;           /* User virtual page. */
    void *kpage;                  /* Kernel virtual page if in memory. */
    enum page_type page_type;     /* Type of page wrt. eviction. */
    bool writable;                /* Indicates if page is writable. */
    struct file *file;            /* Pointer to file for page. */
    uint32_t file_ofs;            /* Offset in file to read data from. */
    uint32_t page_read_bytes;     /* Number of bytes to read from file. */
    uint32_t page_zero_bytes;     /* Number of bytes to zero in page. */
    size_t swap_slot;             /* Swap slot if in swap space. */
  };

hash_hash_func hash_spte;
hash_less_func less_spte;
hash_action_func destroy_spte;
struct spt_entry *get_spt_entry (void *upage, struct thread *t);
void remove_page_from_spt (void *upage);

#endif /* vm/page.h */
