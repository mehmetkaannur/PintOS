#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);

typedef void (*syscall_func_void)(void);
typedef void (*syscall_func_exit)(int);
typedef int  (*syscall_func_int)(const char *);
typedef bool (*syscall_func_bool)(const char *, unsigned);
typedef int  (*syscall_func_fd)(int);
typedef int  (*syscall_func_read_write)(int, void *, unsigned);

static void *syscall_table[] = {
  [SYS_HALT] = (syscall_func_void)halt,
  [SYS_EXIT] = (syscall_func_exit)exit,
  [SYS_EXEC] = (syscall_func_int)exec,
  [SYS_WAIT] = (syscall_func_fd)wait,
  [SYS_CREATE] = (syscall_func_bool)create,
  [SYS_REMOVE] = (syscall_func_int)remove,
  [SYS_OPEN] = (syscall_func_int)open,
  [SYS_FILESIZE] = (syscall_func_fd)filesize,
  [SYS_READ] = (syscall_func_read_write)read,
  [SYS_WRITE] = (syscall_func_read_write)write,
  [SYS_SEEK] = (syscall_func_fd)seek,
  [SYS_TELL] = (syscall_func_fd)tell,
  [SYS_CLOSE] = (syscall_func_fd)close,
  [SYS_MMAP] = (syscall_func_fd)mmap,
  [SYS_MUNMAP] = (syscall_func_fd)munmap,
  [SYS_CHDIR] = (syscall_func_int)chdir,
  [SYS_MKDIR] = (syscall_func_int)mkdir,
  [SYS_READDIR] = (syscall_func_fd)readdir,
  [SYS_ISDIR] = (syscall_func_fd)isdir,
  [SYS_INUMBER] = (syscall_func_fd)inumber
};

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  printf ("system call!\n");
  if (!is_valid_user_pointer(f->esp)) 
    {
      thread_exit();
    }

  int syscall_number = *(int *)f->esp;
  void (*function)() = syscall_table[syscall_number];
  function ();
}
