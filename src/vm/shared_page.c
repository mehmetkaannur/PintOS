#include "vm/shared_page.h"
#include <string.h>
#include "threads/malloc.h"

/* Shared pages hash map */
static struct hash shared_pages;

/* Hash function for shared_page_key */
static unsigned
hash_shared_page_entry (const struct hash_elem *e, void *aux UNUSED)
{
	struct shared_page_entry *spte = hash_entry (e, struct shared_page_entry,
				                                     	 hash_elem);
	return file_hash (spte->file) ^ hash_int (spte->offset);
}

/* Comparison function for shared_page_key */
static bool
less_shared_page_entry (const struct hash_elem *a, const struct hash_elem *b, 
											  void *aux UNUSED)
{
	struct shared_page_entry *entry_a = hash_entry (a, struct shared_page_entry,
																								  hash_elem);
	struct shared_page_entry *entry_b = hash_entry (b, struct shared_page_entry, 
																									hash_elem);

	if (entry_a->file < entry_b->file)
		{
			return true;
		}
	
	if (entry_a->file > entry_b->file)
		{
			return false;
		}

	return entry_a->offset < entry_b->offset;
}

/* Initialize shared pages hash map */
void
shared_pages_init (void)
{
  hash_init (&shared_pages, hash_shared_page_entry,
						 less_shared_page_entry, NULL);
	lock_init (&shared_pages_lock);
}

/* Lookup a shared page; returns pointer to the frame if found, else NULL */
void *
shared_pages_lookup (struct file *file, off_t offset)
{
	struct shared_page_entry temp;
	temp.file = file;
	temp.offset = offset;

	lock_acquire (&shared_pages_lock);

	struct hash_elem *e = hash_find (&shared_pages, &temp.hash_elem);
	struct frame *frame = NULL;
	if (e != NULL)
		{
			struct shared_page_entry *entry = hash_entry (e,
																										struct shared_page_entry, 
														        	 							hash_elem);
			frame = entry->frame;
		}
	
	lock_release (&shared_pages_lock);
	
	return frame;
}

/* Insert a shared page; returns true on success, false on failure */
bool
shared_pages_insert (struct file *file, off_t offset, void *frame)
{
	struct shared_page_entry *new_entry = malloc (sizeof (struct shared_page_entry));
	if (new_entry == NULL)
		{
			return false;
		}

	new_entry->file = file;
	new_entry->offset = offset;
	new_entry->frame = frame;

	lock_acquire (&shared_pages_lock);
	struct hash_elem *existing = hash_insert (&shared_pages,
                                            &new_entry->hash_elem);
	lock_release (&shared_pages_lock);

	if (existing != NULL)
		{
			/* An entry already exists; do not insert */
			free (new_entry);
			return false;
		}

	return true;
}

/* Remove a shared page; returns true on success, false if not found */
bool
shared_pages_remove (struct file *file, off_t offset)
{
	struct shared_page_entry temp;
	temp.file = file;
	temp.offset = offset;

	lock_acquire (&shared_pages_lock);

	struct hash_elem *e = hash_find (&shared_pages, &temp.hash_elem);
	if (e == NULL)
		{
			lock_release (&shared_pages_lock);
			return false;
		}

	struct shared_page_entry *entry = hash_entry (e, struct shared_page_entry, hash_elem);
	hash_delete (&shared_pages, e);

	lock_release (&shared_pages_lock);

	free (entry);
	return true;
}
