#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "hash.h"
#include "threads/synch.h"
#include "filesys/file.h"

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
