#include <user/syscall.h>
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

#define CONSOLE_BUFFER_SIZE 100

/* Functions to handle syscalls. */
static void sys_halt (void *argv[] UNUSED);
static void sys_exit (void *argv[]);
static pid_t sys_exec (void *argv[]);
static int sys_wait (void *argv[]);
static bool sys_create (void *argv[]);
static bool sys_remove (void *argv[]);
static int sys_open (void *argv[]);
static int sys_filesize (void *argv[]);
static int sys_read (void *argv[]);
static int sys_write (void *argv[]);
static void sys_seek (void *argv[]);
static unsigned sys_tell (void *argv[]);
static void sys_close (void *argv[]);
static mapid_t sys_mmap (void *argv[]);
static void sys_munmap (void *argv[]);
static bool sys_chdir (void *argv[]);
static bool sys_mkdir (void *argv[]);
static bool sys_readdir (void *argv[]);
static bool sys_isdir (void *argv[]);
static int sys_inumber (void *argv[]);

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
  [SYS_HALT] = { 0, false, (syscall_func_t) sys_halt },
  [SYS_EXIT] = { 1, false, (syscall_func_t) sys_exit },
  [SYS_EXEC] = { 1, true, (syscall_func_t) sys_exec },
  [SYS_WAIT] = { 1, true, (syscall_func_t) sys_wait },
  [SYS_CREATE] = { 2, true, (syscall_func_t) sys_create },
  [SYS_REMOVE] = { 1, true, (syscall_func_t) sys_remove },
  [SYS_OPEN] = { 1, true, (syscall_func_t) sys_open },
  [SYS_FILESIZE] = { 1, true, (syscall_func_t) sys_filesize },
  [SYS_READ] = { 3, true, (syscall_func_t) sys_read },
  [SYS_WRITE] = { 3, true, (syscall_func_t) sys_write },
  [SYS_SEEK] = { 2, false, (syscall_func_t) sys_seek },
  [SYS_TELL] = { 1, true, (syscall_func_t) sys_tell },
  [SYS_CLOSE] = { 1, false, (syscall_func_t) sys_close },
  [SYS_MMAP] = { 2, true, (syscall_func_t) sys_mmap },
  [SYS_MUNMAP] = { 1, false, (syscall_func_t) sys_munmap },
  [SYS_CHDIR] = { 1, true, (syscall_func_t) sys_chdir },
  [SYS_MKDIR] = { 1, true, (syscall_func_t) sys_mkdir },
  [SYS_READDIR] = { 2, true, (syscall_func_t) sys_readdir },
  [SYS_ISDIR] = { 1, true, (syscall_func_t) sys_isdir },
  [SYS_INUMBER] = { 1, true, (syscall_func_t) sys_inumber }
};

/* Checks if the pointer given by the user is a valid pointer
   and terminates user process if not. */
#ifdef USERPROG
static void
validate_user_pointer (const void *uaddr)
{
  struct thread *t = thread_current ();
  if (!(is_user_vaddr (uaddr) && 
        pagedir_get_page (t->pagedir, uaddr) != NULL))
    {
      thread_exit ();
    }
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
  /* Get info for handling syscall based on syscall_number. */
  validate_user_pointer (f->esp);
  int syscall_number = *(int *) f->esp;
  struct syscall_info info = syscall_table[syscall_number];

  /* Get arguments for syscall function from stack. */
  void *argv[info.argc];
  for (int i = 0; i < info.argc; i++) 
    {
      validate_user_pointer ((int *) f->esp + i + 1); 
      argv[i] = (void *) *((int *) f->esp + i + 1);
    }

  /* Store result of function if any in eax field. */
  int res = (int) info.f (argv);
  if (info.has_result) 
    {
      f->eax = res;
    }
}

static void
sys_halt (void *argv[] UNUSED)
{
  
}

static void
sys_exit (void *argv[])
{
  int status = (int) argv[0];

  struct thread *cur = thread_current ();
  
  /* Set exit status for thread. */
  cur->exit_status = status;
  if (cur->child_info != NULL)
    {
      cur->child_info->status = status;
    }

  thread_exit ();
}

static pid_t
sys_exec (void *argv[])
{
  const char *cmd_line = (const char *) argv[0];
  return process_execute (cmd_line);
}

static int
sys_wait (void *argv[])
{
  int pid = (int) argv[0];
  return process_wait (pid);
}

static bool
sys_create (void *argv[])
{
  const char *file = (const char *) argv[0];
  unsigned initial_size = (unsigned) argv[1];
  return false;
}

static bool
sys_remove (void *argv[])
{
  const char *file = (const char *) argv[0];
  return false;
}

static int
sys_open (void *argv[])
{
  const char *file = (const char *) argv[0];
  return 0;
}

static int
sys_filesize (void *argv[])
{
  int fd = (int) argv[0];
  return 0;
}

static int
sys_read (void *argv[])
{
  int fd = (int) argv[0];
  void *buffer = argv[1];
  unsigned size = (unsigned) argv[2];
  return 0;
}

static int
sys_write (void *argv[])
{
  int fd = (int) argv[0];
  const void *buffer = argv[1];
  unsigned size = (unsigned) argv[2];
  
  if (fd == 1)
    {
      /* Write to console, CONSOLE_BUFFER_SIZE chars at a time. */
      unsigned i;
      for (i = 0; i + CONSOLE_BUFFER_SIZE <= size; i += CONSOLE_BUFFER_SIZE)
        {
          putbuf ((char *) buffer + i, CONSOLE_BUFFER_SIZE);
        }
      putbuf (buffer + i, size - i);

      return size;
    }

  return 0;
}

static void
sys_seek (void *argv[])
{
  int fd = (int) argv[0];
  unsigned position = (unsigned) argv[1];
}

static unsigned
sys_tell (void *argv[])
{
  int fd = (int) argv[0];
  return 0;
}

static void
sys_close (void *argv[])
{
  int fd = (int) argv[0];
}

static mapid_t
sys_mmap (void *argv[])
{
  int fd = (int) argv[0];
  void *addr = argv[1];
  return 0;
}

static void
sys_munmap (void *argv[])
{
  int mapid = (int) argv[0];
}

static bool
sys_chdir (void *argv[])
{
  const char *dir = (const char *) argv[0];
  return false;
}

static bool
sys_mkdir (void *argv[])
{
  const char *dir = (const char *) argv[0];
  return false;
}

static bool
sys_readdir (void *argv[])
{
  int fd = (int) argv[0];
  char *name = (char *) argv[1];
  return false;
}

static bool
sys_isdir (void *argv[])
{
  int fd = (int) argv[0];
  return false;
}

static int
sys_inumber (void *argv[])
{
  int fd = (int) argv[0];
  return 0;
}
