#ifndef VM_SHARED_PAGE_H
#define VM_SHARED_PAGE_H

#include "filesys/file.h"
#include "threads/thread.h"
#include "vm/page.h"
#include "vm/frame.h"
#include <hash.h>

/* Key for shared pages: combination of file and file offset */
struct shared_page_key
	{
    struct file *file;    /* File backing the page */
    off_t offset;         /* Offset within the file */
	};

/* Entry in the shared pages hash map */
struct shared_page_entry
	{
    struct shared_page_key key;        /* Key identifying the shared page */
    struct frame_table_entry *fte;     /* Pointer to the frame table entry */
    struct hash_elem hash_elem;        /* Hash element */
	};

/* Initialize shared pages hash map */
void shared_pages_init (void);

/* Lookup a shared page; returns frame_table_entry if found, else NULL */
struct frame_table_entry *shared_pages_lookup (struct file *file, off_t offset);

/* Insert a shared page; returns true on success, false on failure */
bool shared_pages_insert (struct file *file, off_t offset, 
													struct frame_table_entry *fte);

/* Remove a shared page; returns true on success, false if not found */
bool shared_pages_remove (struct file *file, off_t offset);

#endif /* VM_SHARED_PAGE_H */
