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
#include "userprog/exception.h"
#include "devices/input.h"
#include "filesys/filesys.h"
#include "devices/shutdown.h"
#include "vm/page.h"
#include "vm/frame.h"

/* Maximum stack size of 8MB.*/
#define MAX_STACK_SIZE (1 << 23)
#define STACK_LIMIT ((void *) PHYS_BASE - MAX_STACK_SIZE)
#define CONSOLE_BUFFER_SIZE 100
#define SYS_ERROR -1
#define WORD_SIZE 4

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
static bool sys_chdir (void *argv[] UNUSED);
static bool sys_mkdir (void *argv[] UNUSED);
static bool sys_readdir (void *argv[] UNUSED);
static bool sys_isdir (void *argv[] UNUSED);
static int sys_inumber (void *argv[] UNUSED);

static void syscall_handler (struct intr_frame *);

typedef void *(*syscall_func_t) (void *argv[]);

static void validate_user_pointer (const void *uaddr, bool write);
static bool validate_user_string (const char *uaddr, int max_len, bool write);
static void validate_user_data (const void *uaddr, unsigned size, bool write);

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
validate_user_pointer (const void *uaddr, bool write)
{
  struct thread *t = thread_current ();
  
  /* Attempt to find entry for page in spt. */
  struct spt_entry entry;
  entry.user_page = pg_round_down (uaddr);
  struct hash_elem *e = hash_find (&t->supp_page_table, &entry.elem);

  if (e == NULL)
    {
      /* Check for request to grow stack. */
      if (!is_stack_access (uaddr, thread_current ()->esp))
        {
          thread_exit ();
        }
      return;
    }
      
  /* Check for write to read-only page. */
  struct spt_entry *spte = hash_entry (e, struct spt_entry, elem);
  if (write && !spte->writable)
    {
      thread_exit ();
    }
}

/* Validate a string UADDR provided by user with max length MAX_LEN.
   Returns true if the string has length less than max_len. */
static bool
validate_user_string (const char *uaddr, int max_len, bool write)
{
  for (int i = 0; i <= max_len; i++)
    {
      validate_user_pointer (uaddr + i, write);
      if (uaddr[i] == '\0')
        {
          return true;
        }
    }
  return false;
}

/* Validates user data of given size. */
static void
validate_user_data (const void *uaddr, unsigned size, bool write)
{
  uintptr_t ptr = (uintptr_t) uaddr;
  const uintptr_t end = ptr + size;
  uintptr_t page_boundary = (uintptr_t) pg_round_down (uaddr);
  while (ptr < end)
    {
      /* Check if user-provided pointer is valid. */
      validate_user_pointer ((void *) ptr, write);

      /* Advance to next page boundary or end. */
      page_boundary += PGSIZE;
      ptr = page_boundary < end ? page_boundary : end;
    }
}

/* Helper function to get a file from the hash table of open files. */
static struct file *
get_file_from_fd (int fd)
{
  struct fd_file f;
  f.fd = fd;
  struct hash_elem *e = hash_find (&thread_current ()->fd_file_map,
                                   &f.hash_elem);

  /* Check if file exists in hashmap. */
  if (e == NULL) 
    {
      return NULL;
    }

  return hash_entry (e, struct fd_file, hash_elem)->file;
}

/* Returns true iff the new mapping overlaps existing mappings
   in virtual address space for this user process. */
static bool
check_overlap (void *addr, size_t length)
{
  struct thread *t = thread_current ();
  void *upage = addr;
  size_t size = length;

  while (size > 0) 
    {
      /* If there is an existing spt entry at upage, then the new mapping
         overlaps with an existing mapping. */
      if (get_spt_entry (upage, t) != NULL)
        {
          return true;
        }
      upage += PGSIZE;
      size -= size > PGSIZE ? PGSIZE : size;
    }

  return false;
}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&filesys_lock);
}

/* Handles system calls based on intr_frame f. */
static void
syscall_handler (struct intr_frame *f) 
{
  thread_current ()->esp = f->esp;

  /* Get info for handling syscall based on syscall_number. */
  validate_user_data (f->esp, WORD_SIZE, false);
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
      validate_user_data ((int *) f->esp + i + 1, WORD_SIZE, false);
      argv[i] = (void *) *((int *) f->esp + i + 1);
    }

  /* Store result of function if any in eax field. */
  int res = (int) info.f (argv);
  if (info.has_result) 
    {
      f->eax = res;
    }
}

/* Helper function for halt system call. */
static void
sys_halt (void *argv[] UNUSED)
{
  shutdown_power_off ();
}

/* Helper function for exit system call. */
static void
sys_exit (void *argv[])
{
  int status = (int) argv[0];

  /* Set exit status for thread. */
  thread_current ()->child_info->status = status;

  thread_exit ();
}

/* Helper function for exec system call. */
static pid_t
sys_exec (void *argv[])
{
  const char *cmd_line = (const char *) argv[0];
  if (!validate_user_string (cmd_line, PGSIZE, false))
    {
      return SYS_ERROR;
    }
  
  tid_t tid = process_execute (cmd_line);

  /* Wait for child process to finish load attempt. */
  struct child_info i;
  i.child_pid = (pid_t) tid;
  struct hash_elem *e = hash_find (&thread_current ()->children_map, &i.elem);

  /* Child thread not created successfully. */
  if (e == NULL)
    {
      return SYS_ERROR;
    }
    
  /* Check if child process loaded successfully. */
  struct child_info *child_info = hash_entry (e, struct child_info, elem);
  sema_down (&child_info->load_sema);
  if (!child_info->load_success)
    {
      return SYS_ERROR;
    }

  return tid;
}

/* Helper function for wait system call. */
static int
sys_wait (void *argv[])
{
  int pid = (int) argv[0];
  return process_wait (pid);
}

/* Helper function for create system call. */
static bool
sys_create (void *argv[])
{
  const char *file = (const char *) argv[0];
  unsigned initial_size = (unsigned) argv[1];
  
  /* Check if file name is valid. */
  if (!validate_user_string (file, READDIR_MAX_LEN, false))
    {
      return false;
    }
  
  /* Use buffer from kernel space to prevent page-fault during file-system
     access. */
  size_t len = strlen (file);
  char *kbuffer = malloc (len + 1);
  if (kbuffer == NULL) 
    {
      return false;
    }
  memcpy (kbuffer, file, len + 1);

  /* Create file in file system. */
  lock_acquire (&filesys_lock);
  bool success = filesys_create (kbuffer, initial_size);
  lock_release (&filesys_lock);

  return success;
}

/* Helper function for remove system call. */
static bool
sys_remove (void *argv[])
{
  const char *file = (const char *) argv[0];

  /* Check if file name is valid. */
  if (!validate_user_string (file, READDIR_MAX_LEN, false))
    {
      return false;
    }

  /* Use buffer from kernel space to prevent page-fault during file-system
     access. */
  size_t len = strlen (file);
  char *kbuffer = malloc (len + 1);
  if (kbuffer == NULL) 
    {
      return false;
    }
  memcpy (kbuffer, file, len + 1);
  
  /* Remove file from file system. */
  lock_acquire (&filesys_lock);
  bool success = filesys_remove (kbuffer);
  lock_release (&filesys_lock);

  return success;
}

/* Helper function for open system call. */
static int
sys_open (void *argv[])
{
  const char *file_name = (const char *) argv[0];

  /* Check if file name is valid. */
  if (!validate_user_string (file_name, READDIR_MAX_LEN, false))
    {
      return SYS_ERROR;
    }

  /* Use buffer from kernel space to prevent page-fault during file-system
     access. */
  size_t len = strlen (file_name);
  char *kbuffer = malloc (len + 1);
  if (kbuffer == NULL) 
    {
      return false;
    }
  memcpy (kbuffer, file_name, len + 1);
  
  /* Open file in file system. */
  lock_acquire (&filesys_lock);
  struct file *file = filesys_open (file_name);
  lock_release (&filesys_lock);

  /* Check if file could not be opened. */
  if (file == NULL) 
    {
      return SYS_ERROR;
    }

  struct fd_file *fd_file = malloc (sizeof (struct fd_file));
  
  /* Check if malloc was successful. */
  if (fd_file == NULL) 
    {
      return SYS_ERROR;
    }

  /* Add file to file descriptor map. */
  int fd = thread_current ()->next_fd++;
  fd_file->fd = fd;
  fd_file->file = file;
  hash_insert (&thread_current ()->fd_file_map, &fd_file->hash_elem);

  return fd;
}

/* Helper function for filesize system call. */
static int
sys_filesize (void *argv[])
{
  int fd = (int) argv[0];
  
  /* Attempt to find file with fd. */
  struct file *file = get_file_from_fd (fd);
  if (file == NULL) 
    {
      return SYS_ERROR;
    }

  lock_acquire (&filesys_lock);
  int size = file_length (file);
  lock_release (&filesys_lock);
  
  return size;
}

/* Helper function for read system call. */
static int
sys_read (void *argv[])
{
  int fd = (int) argv[0];
  void *buffer = argv[1];
  unsigned size = (unsigned) argv[2];

  /* Check if buffer is valid. */
  validate_user_data (buffer, size, true);

  if (fd == STDIN_FILENO) 
    {
      /* Read from STDIN. */
      unsigned i;
      for (i = 0; i < size; i++) {
        ((char *) buffer)[i] = input_getc ();
      }
      return size;
    }

  /* Get file from file descriptor. */
  struct file *file = get_file_from_fd (fd);
  if (file == NULL) 
    {
      return SYS_ERROR;
    }
  
  void *kbuffer = palloc_get_page (0);
  if (kbuffer == NULL) 
    {
      return SYS_ERROR;
    }

  /* Read from file one page at a time. Use buffer from kernel space
     to prevent page-fault during filesystem access. */
  int bytes_read = 0;
  for (unsigned i = 0; i < size; i += PGSIZE) 
    {
      unsigned bytes = (size - i) < PGSIZE ? (size - i) : PGSIZE;

      /* Read from file. */
      lock_acquire (&filesys_lock);
      bytes_read += file_read (file, kbuffer, bytes);
      lock_release (&filesys_lock);

      memcpy (buffer + i, kbuffer, bytes);
    }
  palloc_free_page (kbuffer);

  return bytes_read;
}

/* Helper function for write system call. */
static int
sys_write (void *argv[])
{
  int fd = (int) argv[0];
  const void *buffer = argv[1];
  unsigned size = (unsigned) argv[2];

  /* Check if buffer is valid. */
  validate_user_data (buffer, size, false);

  if (fd == STDOUT_FILENO)
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

  /* Get file from file descriptor. */
  struct file *file = get_file_from_fd (fd);
  if (file == NULL) 
    {
      return SYS_ERROR;
    }

  void *kbuffer = palloc_get_page (0);
  if (kbuffer == NULL) 
    {
      return SYS_ERROR;
    }

  /* Write to file-system one page at a time. Use buffer from kernel space
     to prevent page-fault during file-system access. */
  int bytes_write = 0;
  for (unsigned i = 0; i < size; i += PGSIZE) 
    {
      unsigned bytes = (size - i) < PGSIZE ? (size - i) : PGSIZE;

      memcpy (kbuffer, buffer + i, bytes);

      /* Write to file. */
      lock_acquire (&filesys_lock);
      bytes_write += file_write (file, kbuffer, bytes);
      lock_release (&filesys_lock);
    }
  palloc_free_page (kbuffer);

  return bytes_write;
}

/* Helper function for seek system call. */
static void
sys_seek (void *argv[])
{
  int fd = (int) argv[0];
  unsigned position = (unsigned) argv[1];

  /* Get the file from the file descriptor */
  struct file *file = get_file_from_fd (fd);
  if (file == NULL) 
    {
      return;
    }

  /* Change the file position. */
  lock_acquire (&filesys_lock);
  file_seek (file, position);
  lock_release (&filesys_lock);
}

/* Helper function for tell system call. */
static unsigned
sys_tell (void *argv[])
{
  int fd = (int) argv[0];

  /* Get the file from the file descriptor */
  struct file *file = get_file_from_fd (fd);
  if (file == NULL) 
    {
      return SYS_ERROR;
    }
  
  /* Return the position of the next byte to be read or written */
  lock_acquire (&filesys_lock);
  unsigned pos = file_tell (file);
  lock_release (&filesys_lock);

  return pos;
}

/* Helper function for close system call. */
static void
sys_close (void *argv[])
{
  int fd = (int) argv[0];

  /* Remove the file descriptor from the hash table */
  struct fd_file f;
  f.fd = fd;
  struct hash_elem *e = hash_delete (&thread_current ()->fd_file_map,
                                     &f.hash_elem);
  if (e != NULL)
    {
      lock_acquire (&filesys_lock);
      fd_file_destroy (e, NULL);
      lock_release (&filesys_lock);
    }
}

static mapid_t
sys_mmap (void *argv[])
{
  int fd = (int) argv[0];
  void *addr = argv[1];

  /* Find file based on file descriptor FD. */
  struct file *file = get_file_from_fd (fd);
  if (file == NULL) 
    {
      return SYS_ERROR;
    }

  lock_acquire (&filesys_lock);
  size_t length = file_length (file);
  lock_release (&filesys_lock);

  /* Ensure file is not empty. */
  if (length == 0) 
    {
      return SYS_ERROR;
    }

  /* Ensure addr is not 0, is page aligned and does not overlap the space
     reserved for the stack. */
  if (addr == 0
      || pg_ofs (addr) != 0
      || addr + length - 1 >= STACK_LIMIT) 
    {
      return SYS_ERROR;
    }

  /* Check that the mapping does not overlap any existing mappings */
  if (check_overlap (addr, length)) 
    {
      return SYS_ERROR;
    }

  /* Get new file reference for mmapped file. */
  file = file_reopen (file);
  if (file == NULL) 
    {
      return SYS_ERROR;
    }

  struct mmap_file *mmap_file = malloc (sizeof (struct mmap_file));
  if (mmap_file == NULL) 
    {
      file_close (file);
      return SYS_ERROR;
    }

  struct thread *t = thread_current ();

  /* Initialize mmap_file struct. */
  mmap_file->file = file;
  mmap_file->addr = addr;
  mmap_file->length = length;
  mmap_file->mapid = t->next_mapid++;

  hash_insert (&t->mmap_table, &mmap_file->elem);

  /* Add entries to the supplemental page table */
  size_t offset = 0;
  while (length > 0) 
    {
      size_t read_bytes = length < PGSIZE ? length : PGSIZE;
      size_t zero_bytes = PGSIZE - read_bytes;

      void *upage = addr + offset;
      
      struct spt_entry *spte = malloc (sizeof (struct spt_entry));
      if (spte == NULL) 
        {
          file_close (file);
          thread_exit ();
        }

      spte->user_page = upage;
      spte->page_type = MMAP_FILE;
      /* Memory-mapped files are writable by default. */
      spte->writable = true;
      spte->file = file;
      spte->file_ofs = offset;
      spte->page_read_bytes = read_bytes;
      spte->page_zero_bytes = zero_bytes;
      spte->in_memory = false;
      spte->in_swap = false;

      lock_acquire (&t->spt_lock);
      hash_insert (&t->supp_page_table, &spte->elem);
      lock_release (&t->spt_lock);

      offset += PGSIZE;
      length -= read_bytes;
    }

  return mmap_file->mapid;
}

static void
sys_munmap (void *argv[])
{
  mapid_t mapid = (mapid_t) argv[0];
  struct thread *t = thread_current ();

  struct mmap_file temp;
  temp.mapid = mapid;
  struct hash_elem *e = hash_find (&t->mmap_table, &temp.elem);
  if (e == NULL) 
    {
      return;
    }

  struct mmap_file *mmap_file = hash_entry (e, struct mmap_file, elem);

  /* Unmap the file and remove it from the hash table. */
  void *addr = mmap_file->addr;
  size_t length = mmap_file->length;
  size_t offset = 0;

  lock_acquire (&frame_table_lock);
  lock_acquire (&t->io_lock);
  lock_acquire (&t->spt_lock);

  while (length > 0) 
    {
      size_t page_read_bytes = length < PGSIZE ? length : PGSIZE;
      void *upage = addr + offset;
      
      struct spt_entry *spte = get_spt_entry (upage, t);
      hash_delete (&t->supp_page_table, &spte->elem);
      void *frame = spte->kpage;
      bool in_memory = spte->in_memory;
      destroy_spte (&spte->elem, NULL);
      if (in_memory)
        {
          free_frame (frame);
        }
      
      offset += PGSIZE;
      length -= page_read_bytes;
    }

  lock_release (&t->spt_lock);
  lock_release (&t->io_lock);
  lock_release (&frame_table_lock);

  lock_acquire (&filesys_lock);
  file_close (mmap_file->file);
  lock_release (&filesys_lock);

  hash_delete (&t->mmap_table, &mmap_file->elem);
  free (mmap_file);
}

static bool
sys_chdir (void *argv[] UNUSED)
{
  return false;
}

static bool
sys_mkdir (void *argv[] UNUSED)
{
  return false;
}

static bool
sys_readdir (void *argv[] UNUSED)
{
  return false;
}

static bool
sys_isdir (void *argv[] UNUSED)
{
  return false;
}

static int
sys_inumber (void *argv[] UNUSED)
{
  return 0;
}
