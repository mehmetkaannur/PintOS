#include <user/syscall.h>
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "filesys/file.h"
#include "userprog/process.h"
#include "devices/input.h"
#include "filesys/filesys.h"
#include "devices/shutdown.h"

#define CONSOLE_BUFFER_SIZE 100
#define INVALID_FD -1

static int next_fd = 2; /* Next available file descriptor. 0 and 1 are reserved. */

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

static void
check_filename (const char *filename)
{
  if (filename == NULL)
    {
      thread_exit ();
    }
  validate_user_pointer ((const uint32_t *) filename);
}

static int
allocate_fd (void)
{
  return next_fd++;
}

/* Hash function for file descriptor. */
unsigned 
fd_hash (const struct hash_elem *e, void *aux UNUSED) 
{
  const struct fd_file *f = hash_entry (e, struct fd_file, hash_elem);
  return hash_int (f->fd);
}

/* Comparison function for file descriptor. */
bool 
fd_less (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED) 
{
  const struct fd_file *fa = hash_entry (a, struct fd_file, hash_elem);
  const struct fd_file *fb = hash_entry (b, struct fd_file, hash_elem);
  return fa->fd < fb->fd;
}

/* Add a file descriptor and file pointer to the hash table. */
void 
fd_file_map_insert (int fd, struct file *file) 
{
  struct fd_file *f = malloc (sizeof(struct fd_file));
  if (f == NULL) 
    {
      return;
    }
  f->fd = fd;
  f->file = file;
  hash_insert (&fd_file_map, &f->hash_elem);
}

/* Remove a file descriptor and file pointer from the hash table. */
void 
fd_file_map_remove (int fd) 
{
  struct fd_file f;
  f.fd = fd;
  struct hash_elem *e = hash_delete (&fd_file_map, &f.hash_elem);
  if (e != NULL) {
    struct fd_file *fd_file_entry = hash_entry (e, struct fd_file, hash_elem);
    file_allow_write (fd_file_entry->file);
    file_close (fd_file_entry->file);
    free (fd_file_entry);
  }
}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  hash_init (&fd_file_map, fd_hash, fd_less, NULL); // initialize hash table for files
  lock_init (&filesys_lock);
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
  check_filename (file);
  bool success = false;
  if (strlen (file) > READDIR_MAX_LEN)
    {
      return false;
    }
  lock_acquire (&filesys_lock);
  success = filesys_create (file, initial_size);
  lock_release (&filesys_lock);
  return success;
}

static bool
sys_remove (void *argv[])
{
  const char *file = (const char *) argv[0];
  check_filename (file);
  bool success = false;
  lock_acquire (&filesys_lock);
  success = filesys_remove (file);
  lock_release (&filesys_lock);
  return success;
}

static int
sys_open (void *argv[])
{
  const char *file = (const char *) argv[0];
  check_filename (file);

  lock_acquire (&filesys_lock);
  struct file *f = filesys_open (file);
  lock_release (&filesys_lock);
  if (f == NULL) 
    {
      return INVALID_FD; // File could not be opened
    }

  // Allocate a new file descriptor
  int fd = allocate_fd ();
  if (fd == -1) 
    {
      file_close (f);
      return INVALID_FD; // No available file descriptors
    }

  fd_file_map_insert (fd, f);

  return fd;
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
