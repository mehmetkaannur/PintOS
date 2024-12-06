#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "threads/synch.h"
#include "hash.h"
#include <user/syscall.h>
#include <stdbool.h>

struct child_info
  {
    pid_t child_pid;               /* Child's process id. */
    struct semaphore load_sema;    /* Semaphore to indicate child
                                      process has loaded. */
    struct semaphore exit_sema;    /* Semaphore to indicate child
                                      process has exited. */
    struct lock exists_lock;       /* Lock to protect parent_exists and 
                                      child_exists. */
    struct hash_elem elem;         /* Hash elem for parent's children_map. */
    bool load_success;             /* Indicates if child process loaded. */
    bool parent_exists;            /* Indicates if parent still exists. */
    bool child_exists;             /* Indicates if child still exists. */
    int status;                    /* Exit status of child. */
  };

hash_action_func mmap_file_destroy;
hash_action_func fd_file_destroy;

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

bool is_stack_access (const void *uaddr, const void *esp);
void grow_stack (const void *uaddr);

#endif /* userprog/process.h */
