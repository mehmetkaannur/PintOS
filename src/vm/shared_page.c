#include "vm/shared_page.h"
#include <string.h>
#include "threads/malloc.h"

/* Entry in the shared files hash map */
struct shared_file_entry
	{
    struct file *file;              /* File pointer for shared pages. */
    struct hash shared_pages_map;   /* Map of pages at offsets within file. */
    struct hash_elem hash_elem;     /* Hash element */
	};

/* Entry in the shared pages hash map */
struct shared_page_entry
  {
    void *frame;                    /* Frame containing shared page. */
    off_t offset;                   /* Offset within file. */
    struct hash_elem hash_elem;     /* Hash element */
  };

static struct hash shared_files_map;

/* Hash function for shared_page_entry. */
static unsigned
hash_shared_page_entry (const struct hash_elem *e, void *aux UNUSED)
{
	struct shared_page_entry *spte = hash_entry (e, struct shared_page_entry,
				                                     	 hash_elem);
	return hash_int (spte->offset);
}

/* Comparator function for shared_page_entry. */
static bool
less_shared_page_entry (const struct hash_elem *a, const struct hash_elem *b, 
											  void *aux UNUSED)
{
	struct shared_page_entry *entry_a = hash_entry (a, struct shared_page_entry,
																								  hash_elem);
	struct shared_page_entry *entry_b = hash_entry (b, struct shared_page_entry, 
																									hash_elem);

  return entry_a->offset < entry_b->offset;
}

/* Hash function for shared_file_entry. */
static unsigned
hash_shared_file_entry (const struct hash_elem *e, void *aux UNUSED)
{
  struct shared_file_entry *sfe = hash_entry (e, struct shared_file_entry,
                                             	 hash_elem);
  return hash_ptr (sfe->file);
}

/* Comparator function for shared_file_entry. */
static bool
less_shared_file_entry (const struct hash_elem *a, const struct hash_elem *b, 
                       void *aux UNUSED)
{
  struct shared_file_entry *entry_a = hash_entry (a, struct shared_file_entry,
                                                  hash_elem);
  struct shared_file_entry *entry_b = hash_entry (b, struct shared_file_entry, 
                                                  hash_elem);

  return entry_a->file < entry_b->file;
}

/* Initialize shared pages hash map */
void
shared_pages_init (void)
{
  hash_init (&shared_files_map, hash_shared_file_entry,
						 less_shared_file_entry, NULL);
	lock_init (&shared_pages_lock);
}

/* Lookup a shared page; returns pointer to the frame if found, else NULL */
void *
shared_pages_lookup (struct file *file, off_t offset)
{
	struct shared_file_entry temp;
	temp.file = file;

  /* Find entry for file FILE in shared files map. */
	struct hash_elem *e = hash_find (&shared_files_map, &temp.hash_elem);

  if (e == NULL)
    {
      return NULL;
    }

  struct shared_file_entry *entry = hash_entry (e,
                                                struct shared_file_entry, 
                                                hash_elem);

  struct shared_page_entry temp2;
  temp2.offset = offset;

  /* Find entry for page with offset OFFSET in the shared_pages_map
     for file FILE. */
  e = hash_find (&entry->shared_pages_map, &temp2.hash_elem);

  if (e == NULL)
    {
      return NULL;
    }
    
  struct shared_page_entry *spe = hash_entry (e, struct shared_page_entry,
                                              hash_elem);
	
	return spe->frame;
}

/* Insert a shared page; returns true on success, false on failure.
   Shared pages lock must be held on entry to this function. */
bool
shared_pages_insert (struct file *file, off_t offset, void *frame)
{
  struct shared_file_entry temp;
  temp.file = file;

  /* Find entry for file FILE in shared_files_map. */
  struct hash_elem *e = hash_find (&shared_files_map, &temp.hash_elem);
  struct shared_file_entry *entry; 

  /* This file has not had any shared pages yet. */
  if (e == NULL)
    {
      /* Create a new entry for this file to have pages shared. */
      entry = malloc (sizeof (struct shared_file_entry));
      if (entry == NULL)
        {
          return false;
        }

      entry->file = file;
      if (hash_init (&entry->shared_pages_map, hash_shared_page_entry,
                     less_shared_page_entry, NULL))
        {
          free (entry);
          return false;
        }

      hash_insert (&shared_files_map, &entry->hash_elem);
    }
  else
    {
      entry = hash_entry (e, struct shared_file_entry, hash_elem);
    }

  /* Create entry for page with offset OFFSET in the file FILE.*/
  struct shared_page_entry *spe = malloc (sizeof (struct shared_page_entry));
  if (spe == NULL)
    {
      return false;
    }
  
  spe->frame = frame;
  spe->offset = offset;

  hash_insert (&entry->shared_pages_map, &spe->hash_elem);

  return true;
}

/* Remove a shared page. */
void
shared_pages_remove (struct file *file, off_t offset)
{
	struct shared_file_entry temp;
	temp.file = file;

  /* Find entry for file FILE in shared_files_map. */
	struct hash_elem *e = hash_find (&shared_files_map, &temp.hash_elem);
  if (e == NULL)
    {
      return;
    }

	struct shared_file_entry *entry = hash_entry (e,
                                                struct shared_file_entry,
                                                hash_elem);

  struct shared_page_entry temp2;
  temp2.offset = offset;

  /* Find entry for page with offset OFFSET in the shared_pages_map
     for file FILE. */
  e = hash_find (&entry->shared_pages_map, &temp2.hash_elem);
  if (e == NULL)
    {
      return;
    }

  struct shared_page_entry *spe = hash_entry (e, struct shared_page_entry,
                                              hash_elem);

  hash_delete (&entry->shared_pages_map, &spe->hash_elem);
  free (spe);

  if (hash_empty (&entry->shared_pages_map))
    {
      hash_delete (&shared_files_map, &entry->hash_elem);
      free (entry);
    }
}

/* Returns true iff the page corresponding to the spt entry SPTE
   is shareable. */
bool
is_shareable (struct spt_entry *spte)
{
	return (spte->page_type == EXEC_FILE && !spte->writable)
         || spte->page_type == MMAP_FILE;
}
