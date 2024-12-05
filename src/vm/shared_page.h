#ifndef VM_SHARED_PAGE_H
#define VM_SHARED_PAGE_H

#include "filesys/file.h"
#include "threads/thread.h"
#include "vm/page.h"
#include "vm/frame.h"
#include <hash.h>
#include "threads/synch.h"
#include "filesys/off_t.h"

/* Entry in the shared pages hash map */
struct shared_page_entry
	{
    struct file *file;                 /* File backing the page */
    off_t offset;                      /* Offset within the file */
    void *frame;                       /* Frame containing the page */
    struct hash_elem hash_elem;        /* Hash element */
	};

/* Lock to access shared_pages hash map. */
struct lock shared_pages_lock;

/* Initialize shared pages hash map */
void shared_pages_init (void);

/* Lookup a shared page and returns the frame containing that pa */
void *shared_pages_lookup (struct file *file, off_t offset);

/* Insert a shared page; returns true on success, false on failure */
bool shared_pages_insert (struct file *file, off_t offset, void *frame);

/* Remove a shared page; returns true on success, false if not found */
void shared_pages_remove (struct file *file, off_t offset);

/* Check if page is shareable using spt entry. */
bool is_shareable (struct spt_entry *spte);

#endif /* VM_SHARED_PAGE_H */
