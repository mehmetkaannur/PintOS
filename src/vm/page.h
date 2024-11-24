#include <hash.h>

/* Possible states of a page not in memory, recorded in SPT. */
enum page_state
  {
    SWAPPED,                      /* Page is swapped out. */
    FILE_SYSTEM,                  /* Page is in file system. */
    MMAP_FILE                     /* Page is part of a memory-mapped file. */
  };

/* Supplemental page table entry (SPT). */
struct spt_entry
  {
    struct hash_elem elem;        /* Hash element for thread's
                                     supplemental page table. */
    uint8_t *user_page;           /* User virtual page. */
    enum page_state state;        /* State of the page. */
    bool writable;                /* Indicates if page is writable. */
    struct file *file;            /* Pointer to file contain data for page. */
    uint32_t file_ofs;            /* Offset in file to read data from. */
    uint32_t page_read_bytes;     /* Number of bytes to read from file. */
    uint32_t page_zero_bytes;     /* Number of bytes to zero in page. */

    /* For memory-mapped files. */
    bool is_mmap;                 /* True if the page is memory-mapped. */
    struct mmap_file *mmap_file;  /* Pointer to the mmap_file structure. */

    bool loaded;                  /* True if the page is loaded into memory. */
  };

hash_hash_func hash_spt;
hash_less_func less_spt;
