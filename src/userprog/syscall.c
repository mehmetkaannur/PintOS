#include <user/syscall.h>
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <string.h>
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
#define STDIN 0
#define STDOUT 1

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
static void
validate_user_pointer (const void *uaddr)
{
  struct thread *t = thread_current ();
  if (!(is_user_vaddr (uaddr) && 
        pagedir_get_page (t->pagedir, uaddr) != NULL))
    {
      t->exit_status = -1;
      thread_exit ();
    }
}

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
  struct thread *t = thread_current ();
  return t->next_fd++;
}

static void
validate_user_buffer (const void *buffer, unsigned size)
{
  const uint8_t *ptr = (const uint8_t *) buffer;
  const uint8_t *end = ptr + size;
  while (ptr < end)
    {
      validate_user_pointer (ptr);
      /* Advance to next page boundary or end */
      uintptr_t page_boundary = ((uintptr_t) ptr & ~PGMASK) + PGSIZE;
      if (page_boundary < (uintptr_t) end)
        {
          ptr = (const uint8_t *) page_boundary;
        }
      else
        {
          ptr = end;
        }
    }
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
  hash_insert (&thread_current ()->fd_file_map, &f->hash_elem);
}

/* Remove a file descriptor and file pointer from the hash table. */
void 
fd_file_map_remove (int fd) 
{
  struct fd_file f;
  f.fd = fd;
  struct hash_elem *e = hash_delete (&thread_current ()->fd_file_map,
                                     &f.hash_elem);
  if (e != NULL) {
    struct fd_file *fd_file_entry = hash_entry (e, struct fd_file, hash_elem);
    file_close (fd_file_entry->file);
    free (fd_file_entry);
  }
}

/* Helper function to get a file from the hash table of open files. */
static struct file *
get_file_from_fd(int fd)
{
  struct fd_file f;
  f.fd = fd;
  struct hash_elem *e = hash_find (&thread_current ()->fd_file_map,
                                   &f.hash_elem);
  if (e == NULL) 
    {
      return NULL; // File doesn't exist
    }
  struct fd_file *fd_file_entry = hash_entry (e, struct fd_file, hash_elem);
  // TODO: do we need to check if fd_file_entry is NULL?
  return fd_file_entry->file;
}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&filesys_lock);
}

static void
syscall_handler (struct intr_frame *f) 
{
  /* Get info for handling syscall based on syscall_number. */
  validate_user_pointer (f->esp);
  int syscall_number = *(int *) f->esp;
  int syscall_entries = sizeof (syscall_table) / sizeof (struct syscall_info);
  if (syscall_number < 0 || syscall_number >= syscall_entries)
    {
      thread_exit ();
    }
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
  shutdown_power_off ();
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
  tid_t tid = process_execute (cmd_line);

  /* Wait for child process to finish load attempt. */
  struct child_info i;
  i.child_pid = (pid_t) tid;
  struct hash_elem *e = hash_find (&thread_current ()->children_map, &i.elem);

  /* Child thread not created successfully. */
  if (e == NULL)
    {
      return -1;
    }
    
  /* Check if child process loaded successfully. */
  struct child_info *child_info = hash_entry (e, struct child_info, elem);
  sema_down (&child_info->load_sema);
  if (!child_info->load_success)
    {
      return -1;
    }

  return tid;
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
  lock_acquire (&filesys_lock);
  struct file *file = get_file_from_fd (fd);
  if (file == NULL) 
    {
      lock_release (&filesys_lock);
      return INVALID_FD;
    }

  int size = file_length (file);
  lock_release (&filesys_lock);
  return size;
}

static int
sys_read (void *argv[])
{
  int fd = (int) argv[0];
  void *buffer = argv[1];
  unsigned size = (unsigned) argv[2];

  validate_user_buffer (buffer, size);
  if (fd == 0) 
    {
      // Read from the keyboard
      unsigned i;
      for (i = 0; i < size; i++) {
        ((char *)buffer)[i] = input_getc ();
      }
      return size;
    }
  else if (fd == 1)
    {
      return -1;
    }

  lock_acquire (&filesys_lock);
  struct file *file = get_file_from_fd (fd);
  if (file == NULL) 
    {
      lock_release (&filesys_lock);
      return INVALID_FD;
    }
  int bytes_read = file_read (file, buffer, size);
  lock_release (&filesys_lock);

  return bytes_read;
}

static int
sys_write (void *argv[])
{
  // file_deny_write is called in load() in process.c
  // TODO: file_allow_write() need to be called properly
  int fd = (int) argv[0];
  const void *buffer = argv[1];
  unsigned size = (unsigned) argv[2];
  
  validate_user_buffer (buffer, size);
  if (fd == STDOUT)
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
  else if (fd <= STDIN) 
    {
      return 0; // should we return -1 or 0?
    }

  lock_acquire (&filesys_lock);
  struct file *file = get_file_from_fd (fd);
  if (file == NULL) 
    {
      lock_release (&filesys_lock);
      return INVALID_FD;
    }
  int bytes_write = file_write (file, buffer, size);
  lock_release (&filesys_lock);

  return bytes_write;
}

static void
sys_seek (void *argv[])
{
  int fd = (int) argv[0];
  unsigned position = (unsigned) argv[1];
  if (fd == 0 || fd == 1) 
    {
      return;
    }
  lock_acquire (&filesys_lock);
  struct file *file = get_file_from_fd (fd);
  if (file == NULL) 
    {
      lock_release (&filesys_lock);
      return;
    }
  file_seek (file, position); // change the file position
  lock_release (&filesys_lock);
}

static unsigned
sys_tell (void *argv[])
{
  int fd = (int) argv[0];
  if (fd == 0 || fd == 1) 
    {
      return -1;
    }
  lock_acquire (&filesys_lock);
  struct file *file = get_file_from_fd (fd);

  if (file == NULL) 
    {
      lock_release (&filesys_lock);
      return INVALID_FD;
    }
  
  // Return the position of the next byte to be read or written
  unsigned pos = file_tell (file);
  lock_release (&filesys_lock);
  return pos;
}

static void
sys_close (void *argv[])
{
  int fd = (int) argv[0];
  if (fd <= STDOUT) // STDIN (0) and STDOUT (1) cannot be closed
    {
      return;
    }
  lock_acquire (&filesys_lock);
  fd_file_map_remove (fd);
  lock_release (&filesys_lock);
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
