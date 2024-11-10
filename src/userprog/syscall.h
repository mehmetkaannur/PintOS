#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "hash.h"
#include "threads/synch.h"
#include "filesys/file.h"

void syscall_init (void);
unsigned fd_hash (const struct hash_elem *e, void *aux);
bool fd_less (const struct hash_elem *a, const struct hash_elem *b, void *aux);
void fd_file_map_insert (int fd, struct file *file);
void fd_file_map_remove (int fd);

// Structure to hold file descriptor and file pointer.
struct fd_file {
  int fd;
  struct file *file;
  struct hash_elem hash_elem;
};

// Lock structure to synchronize file system operations.
struct lock filesys_lock;

#endif /* userprog/syscall.h */
