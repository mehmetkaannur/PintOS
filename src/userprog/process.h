#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "threads/synch.h"
#include "hash.h"
#include <user/syscall.h>

struct child_info
  {
    pid_t child_pid;
    struct thread *child;
    struct semaphore sema;
    struct hash_elem elem;
    int status;
  };

hash_hash_func hash_child_info;
hash_less_func less_child_info;

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

#endif /* userprog/process.h */
