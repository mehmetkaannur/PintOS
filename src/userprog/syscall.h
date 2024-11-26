#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "hash.h"
#include "threads/synch.h"
#include "filesys/file.h"
#include "threads/thread.h"

/* Represents a memory-mapped file */
struct mmap_file 
  {
    mapid_t mapid;               /* Mapping ID */
    void *addr;                  /* Start address of the mapping */
    size_t length;               /* Length of the mapping */
    struct hash_elem elem;       /* Hash element for process's mmap
                                    hash table. */
  };

void syscall_init (void);

/* File with file descriptor (fd). */
struct fd_file
  {
    int fd;                               /* File descriptor. */
    struct file *file;                    /* File pointer. */ 
    struct hash_elem hash_elem;           /* Hash element. */
  };

/* Lock to synchronize file system operations. */
struct lock filesys_lock;

#endif /* userprog/syscall.h */
