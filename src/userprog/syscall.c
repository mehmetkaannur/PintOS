#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

/* Functions to handle syscalls. */
static void halt (void *argv[] UNUSED);
static void exit (void *argv[]);
static int exec (void *argv[]);
static int wait (void *argv[]);
static bool create (void *argv[]);
static int remove (void *argv[]);
static int open (void *argv[]);
static int filesize (void *argv[]);
static int read (void *argv[]);
static int write (void *argv[]);
static int seek (void *argv[]);
static int tell (void *argv[]);
static int close (void *argv[]);
static int mmap (void *argv[]);
static int munmap (void *argv[]);
static int chdir (void *argv[]);
static int mkdir (void *argv[]);
static int readdir (void *argv[]);
static int isdir (void *argv[]);
static int inumber (void *argv[]);

static void syscall_handler (struct intr_frame *);

typedef void *(*syscall_func_t) (void *argv[]);

/* Entry with information on how to handle syscall. */
struct syscall_info
  {
    int argc;          /* The number of arguments used by syscall function. */
    bool has_result;   /* Whether or not syscall function returns anything. */
    syscall_func_t f;  /* Function to handle syscall. */
  };

/* Mapping of syscall_numbers to information to handle syscall. */
static struct syscall_info syscall_table[] = {
  [SYS_HALT] = { 0, false, (syscall_func_t) halt },
  [SYS_EXIT] = { 1, false, (syscall_func_t) exit },
  [SYS_EXEC] = { 1, true, (syscall_func_t) exec },
  [SYS_WAIT] = { 1, true, (syscall_func_t) wait },
  [SYS_CREATE] = { 2, true, (syscall_func_t) create },
  [SYS_REMOVE] = { 1, true, (syscall_func_t) remove },
  [SYS_OPEN] = { 1, true, (syscall_func_t) open },
  [SYS_FILESIZE] = { 1, true, (syscall_func_t) filesize },
  [SYS_READ] = { 3, true, (syscall_func_t) read },
  [SYS_WRITE] = { 3, true, (syscall_func_t) write },
  [SYS_SEEK] = { 2, false, (syscall_func_t) seek },
  [SYS_TELL] = { 1, true, (syscall_func_t) tell },
  [SYS_CLOSE] = { 1, false, (syscall_func_t) close },
  [SYS_MMAP] = { 2, true, (syscall_func_t) mmap },
  [SYS_MUNMAP] = { 1, true, (syscall_func_t) munmap },
  [SYS_CHDIR] = { 1, true, (syscall_func_t) chdir },
  [SYS_MKDIR] = { 1, true, (syscall_func_t) mkdir },
  [SYS_READDIR] = { 2, true, (syscall_func_t) readdir },
  [SYS_ISDIR] = { 1, true, (syscall_func_t) isdir },
  [SYS_INUMBER] = { 1, true, (syscall_func_t) inumber }
};

/* Checks if the pointer given by the user is a valid pointer. */
#ifdef USERPROG
static bool
is_valid_user_pointer (const void *uaddr)
{
  struct thread *t = thread_current ();
  return is_user_vaddr (uaddr) && 
         pagedir_get_page (t->pagedir, uaddr) != NULL;
}
#endif

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  if (!is_valid_user_pointer (f->esp)) 
    {
      thread_exit();
    }

  int syscall_number = *(int *) f->esp;
  struct syscall_info info = syscall_table[syscall_number];

  void *argv[info.argc];

  for (int i = 0; i < info.argc; i++) 
    {
      argv[i] = (void *) *((int *) f->esp + i + 1);
      if (!is_valid_user_pointer (argv[i])) 
        {
          thread_exit ();
        }
    }

  int res = (int) info.f (argv);

  if (info.has_result) 
    {
      f->eax = res;
    }
}

static void halt (void *argv[] UNUSED) {}

static void exit (void *argv[]) {
  int status = *(int *) argv[0];
}

static int exec (void *argv[]) {
  const char *cmd_line = (const char *) argv[0];
  return 0;
}

static int wait (void *argv[]) {
  int pid = *(int *) argv[0];
  return 0;
}

static bool create (void *argv[]) {
  const char *file = (const char *) argv[0];
  unsigned initial_size = *(unsigned *) argv[1];
  return false;
}

static int remove (void *argv[]) {
  const char *file = (const char *) argv[0];
  return 0;
}

static int open (void *argv[]) {
  const char *file = (const char *) argv[0];
  return 0;
}

static int filesize (void *argv[]) {
  int fd = *(int *) argv[0];
  return 0;
}

static int read (void *argv[]) {
  int fd = *(int *) argv[0];
  void *buffer = argv[1];
  unsigned size = *(unsigned *) argv[2];
  return 0;
}

static int write (void *argv[]) {
  int fd = *(int *) argv[0];
  const void *buffer = argv[1];
  unsigned size = *(unsigned *) argv[2];
  return 0;
}

static int seek (void *argv[]) {
  int fd = *(int *) argv[0];
  unsigned position = *(unsigned *) argv[1];
  return 0;
}

static int tell (void *argv[]) {
  int fd = *(int *) argv[0];
  return 0;
}

static int close (void *argv[]) {
  int fd = *(int *) argv[0];
  return 0;
}

static int mmap (void *argv[]) {
  int fd = *(int *) argv[0];
  void *addr = argv[1];
  return 0;
}

static int munmap (void *argv[]) {
  int mapid = *(int *) argv[0];
  return 0;
}

static int chdir (void *argv[]) {
  const char *dir = (const char *) argv[0];
  return 0;
}

static int mkdir (void *argv[]) {
  const char *dir = (const char *) argv[0];
  return 0;
}

static int readdir (void *argv[]) {
  int fd = *(int *) argv[0];
  char *name = (char *) argv[1];
  return 0;
}

static int isdir (void *argv[]) {
  int fd = *(int *) argv[0];
  return 0;
}

static int inumber (void *argv[]) {
  int fd = *(int *) argv[0];
  return 0;
}