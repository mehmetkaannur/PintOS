#include "vm/shared_page.h"
#include <string.h>
#include "threads/malloc.h"

/* Hash function for shared_page_key */
static unsigned
hash_shared_page_key (const struct hash_elem *e, void *aux UNUSED)
{
	const struct shared_page_entry *entry = hash_entry (e, struct shared_page_entry, 
																											hash_elem);
	unsigned hash = hash_bytes (&entry->key, sizeof (entry->key));
	return hash;
}

/* Comparison function for shared_page_key */
static bool
less_shared_page_key (const struct hash_elem *a, const struct hash_elem *b, 
											void *aux UNUSED)
{
	const struct shared_page_entry *entry_a = hash_entry (a, struct shared_page_entry, 
																												hash_elem);
	const struct shared_page_entry *entry_b = hash_entry (b, struct shared_page_entry, 
																												hash_elem);

	if (entry_a->key.file < entry_b->key.file)
		{
			return true;
		}
	else if (entry_a->key.file > entry_b->key.file)
		{
			return false;
		}
	else
		{
			return entry_a->key.offset < entry_b->key.offset;
		}
}

/* Hash function for frame_table_entry */
unsigned
hash_frame_table_entry (const struct hash_elem *e, void *aux UNUSED)
{
    const struct frame_table_entry *fte = hash_entry (e, struct frame_table_entry, 
																											hash_elem);
    return hash_bytes (&fte->frame, sizeof (fte->frame));
}

/* Less function for frame_table_entry */
bool
less_frame_table_entry (const struct hash_elem *a, const struct hash_elem *b, 
												void *aux UNUSED)
{
	const struct frame_table_entry *fte_a = hash_entry (a, struct frame_table_entry, 
																											hash_elem);
	const struct frame_table_entry *fte_b = hash_entry (b, struct frame_table_entry, 
																											hash_elem);
	return fte_a->frame < fte_b->frame;
}

/* Shared pages hash map */
static struct hash shared_pages;

/* Initialize shared pages hash map */
void
shared_pages_init (void)
{
    hash_init (&shared_pages, hash_shared_page_key, less_shared_page_key, NULL);
}

/* Lookup a shared page; returns frame_table_entry if found, else NULL */
struct frame_table_entry *
shared_pages_lookup (struct file *file, off_t offset)
{
	struct shared_page_entry temp;
	temp.key.file = file;
	temp.key.offset = offset;

	// lock_acquire(&frame_table_lock);
	struct hash_elem *e = hash_find (&shared_pages, &temp.hash_elem);
	struct frame_table_entry *fte = NULL;
	if (e != NULL)
		{
			struct shared_page_entry *entry = hash_entry (e, struct shared_page_entry, 
																										hash_elem);
			fte = entry->fte;
		}
	// lock_release(&frame_table_lock);
	return fte;
}

/* Insert a shared page; returns true on success, false on failure */
bool
shared_pages_insert (struct file *file, off_t offset, struct frame_table_entry *fte)
{
	struct shared_page_entry *new_entry = malloc (sizeof (struct shared_page_entry));
	if (new_entry == NULL)
		{
			return false;
		}

	new_entry->key.file = file;
	new_entry->key.offset = offset;
	new_entry->fte = fte;

	// lock_acquire(&frame_table_lock);
	struct hash_elem *existing = hash_insert (&shared_pages, &new_entry->hash_elem);
	// lock_release(&frame_table_lock);

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
	temp.key.file = file;
	temp.key.offset = offset;

	// lock_acquire(&frame_table_lock);
	struct hash_elem *e = hash_find (&shared_pages, &temp.hash_elem);
	if (e == NULL)
		{
			// lock_release(&frame_table_lock);
			return false;
		}
	struct shared_page_entry *entry = hash_entry (e, struct shared_page_entry, hash_elem);
	hash_delete (&shared_pages, e);
	// lock_release(&frame_table_lock);

	free (entry);
	return true;
}
