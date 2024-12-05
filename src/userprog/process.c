#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <hash.h>
#include <user/syscall.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include "userprog/syscall.h"
#include "vm/frame.h"
#include "vm/page.h"
#include "vm/shared_page.h"

/* Maximum stack size of 8MB.*/
#define MAX_STACK_SIZE (1 << 23)
#define WORD_SIZE 4
#define NUM_ADDITIONAL_STACK_ADDRS 4
#define PUSHA_SIZE 32
#define PUSH_SIZE 4

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);
static void setup_stack_args (int argc, char *argv[], void **esp);
static void child_info_destroy (struct hash_elem *e, void *aux UNUSED);
static void push_to_stack (void *arg, char **esp, size_t size);
static void push_string_to_stack (char *arg, char **esp);

/* Argument passing information for start_process. */
struct process_args
  {
    char **argv;              /* Array of arguments. */
    int argc;                 /* Number of arguments. */
  };

/* Destroys child_info struct. */
static void
child_info_destroy (struct hash_elem *e, void *aux UNUSED)
{
  struct child_info *i = hash_entry (e, struct child_info, elem);
  
  bool should_free = false;
  lock_acquire (&i->exists_lock);
  /* If child does not exist, since parent is dying, free child_info. */
  if (i->child_exists)
    {
      i->parent_exists = false;
    }
  else
    {
      should_free = true;
    }
  lock_release (&i->exists_lock);

  /* We do not have to worry about the child thread accessing child_info
     struct after free because it is necessarily dead (or won't access the
     child_info struct again at least). */ 
  if (should_free)
    {
      free (i);
    }
}

/* Destroys mmap_file struct. */
void
mmap_file_destroy (struct hash_elem *e, void *aux UNUSED)
{
  struct mmap_file *mmap_file = hash_entry (e, struct mmap_file, elem);
  file_close (mmap_file->file);
  free (mmap_file);
}

/* Destroys fd_file struct. Caller must hold the file_sys lock.  */
void
fd_file_destroy (struct hash_elem *e, void *aux UNUSED)
{
  struct fd_file *i = hash_entry (e, struct fd_file, hash_elem);
  file_close (i->file);
  free (i);
}

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *command) 
{
  char *cmd_copy;
  tid_t tid;
  
  /* Make a copy of command.
     Otherwise there's a race between the caller and load(). */
  cmd_copy = palloc_get_page (0);
  if (cmd_copy == NULL)
    return TID_ERROR;
  strlcpy (cmd_copy, command, PGSIZE);

  char *sep = " ";
  char *arg, *last;
  int argc = 0;

  /* Monitor projected stack_size to detect potential overflow. */  
  size_t stack_size = NUM_ADDITIONAL_STACK_ADDRS * sizeof (void *);
  
  /* Maximum possible arguments from command string occurs if every other
    character is an argument (e.g. "a b c" has 5 characters and 3 args). */
  size_t max_cmd_args = (strlen (cmd_copy) + 1) / 2;

  /* Maximum possible arguments on stack occurs when each tokenised arg
     has 1 character and a null terminator (e.g. "a\0"). */
  size_t max_allowed_args = (MAX_STACK_SIZE - stack_size) 
                           / (sizeof (char) * 2 + sizeof (char *));

  /* The number of arguments is limited by the maximum that will fit on the
      stack and the maximum that can come from the command string. */ 
  size_t argv_size = max_cmd_args > max_allowed_args
                   ? max_allowed_args : max_cmd_args;
  char **argv = malloc (argv_size * sizeof (char *));

  /* Check if malloc was successful. */
  if (argv == NULL)
    {
      palloc_free_page (cmd_copy);
      return TID_ERROR;
    }

  /* Tokenise command string into file name and arguments, up to maximum
     number of arguments possible. */
  for (arg = strtok_r (cmd_copy, sep, &last);
       arg && argc < (int) argv_size;
       arg = strtok_r (NULL, sep, &last))
    {
      argv[argc] = arg;
      argc++;
      stack_size += strlen (arg) + 1;
    }

  /* Round up stack size to multiple of 4 (WORD_SIZE) bytes. */
  stack_size = (stack_size + (WORD_SIZE - 1)) & ~(WORD_SIZE - 1);
  
  /* Calculate projected size of stack after setup with args. */
  stack_size += argc * (int) sizeof (char *);

  /* Check if size of arguments in command too large or too many arguments. */
  if (stack_size > PGSIZE || arg)
    {
      free (argv);
      palloc_free_page (cmd_copy);
      return TID_ERROR;
    }
  
  /* Create struct to pass arguments to start_process. */
  struct process_args *args = malloc (sizeof (struct process_args));

  /* Check if malloc was successful. */
  if (args == NULL)
    {
      free (argv);
      palloc_free_page (cmd_copy);
      return TID_ERROR;
    }

  args->argc = argc;
  args->argv = argv;

  tid = thread_create (argv[0], PRI_DEFAULT, start_process, args);
 
  /* Check if thread_create was successful. */
  if (tid == TID_ERROR)
    {
      free (args);
      free (argv);
      palloc_free_page (cmd_copy);
    }
  
  return tid;
}

/* Grow user stack if required. */
bool
grow_stack (const void *uaddr, const void *esp)
{
  /* Check we are handling a user virtual address. */
  if (is_kernel_vaddr (uaddr))
    {
      return false;
    }

  /* Check for stack that is too large. */
  if (uaddr < PHYS_BASE - MAX_STACK_SIZE)
    {
      return false;
    }

  /* Check for stack growth request. */  
  int diff = esp - uaddr;
  if (uaddr >= esp || diff == PUSHA_SIZE || diff == PUSH_SIZE)
    {
      struct thread *cur = thread_current ();
      void *frame = get_frame (PAL_USER);
      if (frame != NULL)
        {
          bool success = pagedir_set_page (cur->pagedir,
                                           pg_round_down (uaddr),
                                           frame,
                                           true);
          if (!success)
            {
              lock_acquire (&frame_table_lock);
              free_frame (frame);
              lock_release (&frame_table_lock);
            }
          else
            {
              /* Add entry for page in supplemental page table. */
              struct spt_entry *spte = malloc (sizeof (struct spt_entry));
              if (spte == NULL)
                {
                  return false;
                }

              spte->in_memory = true;
              spte->is_pinned = false;
              spte->user_page = pg_round_down (uaddr);
              spte->page_type = STACK;
              spte->in_swap = false;
              spte->writable = true;
              spte->kpage = frame;

              lock_acquire (&cur->spt_lock);
              hash_insert (&cur->supp_page_table, &spte->elem);         
              lock_release (&cur->spt_lock);
            }
          return success;
        }
    }
  return false;

}

/* Push argument ARG of size SIZE to stack given by ESP. */
static void
push_to_stack (void *arg, char **esp, size_t size)
{
  *esp -= size;
  memcpy (*esp, &arg, size);
}

/* Push string argument ARG to stack given by ESP. */
static void
push_string_to_stack (char *arg, char **esp)
{
  size_t arglen = strlen (arg) + 1; 
  *esp -= arglen;
  strlcpy (*esp, arg, arglen);
}

/* Setup stack with arguments according to 80x86 calling convention. */
static void
setup_stack_args (int argc, char *argv[], void **sp_)
{
  /* Malloc array to prevent overflow of stack. */
  char **argvp = malloc (argc * sizeof (char *));
  
  /* Check if malloc was successful. */
  if (argvp == NULL)
    {
      thread_exit ();
    }

  char **sp = (char **) sp_;

  /* Push arguments to stack. */
  for (int i = argc - 1; i >= 0; i--)
    {
      push_string_to_stack (argv[i], sp);
      argvp[i] = *sp;
    }
  
  /* Round stack pointer to multiple of 4 for word alignment. */
  *sp = (void *) ((uintptr_t) (*sp) & ~(WORD_SIZE - 1));

  /* Add null pointer to stack. */
  push_to_stack (NULL, sp, sizeof (char *));

  /* Add addresses of arguments to stack in right to left order. */
  for (int i = argc - 1; i >= 0; i--)
    {
      push_to_stack (argvp[i], sp, sizeof (char *));
    }

  /* Add address of array of argument addresses to stack. */
  push_to_stack (*sp, sp, sizeof (char **));

  /* Add argc value to stack. */
  push_to_stack ((void *) argc, sp, sizeof (int));

  /* Add fake return address to stack. */
  push_to_stack (NULL, sp, sizeof (void *));
  
  free (argvp);
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *args_)
{
  struct process_args *args = (struct process_args *) args_;
  struct thread *cur = thread_current ();
  struct intr_frame if_;
  bool success;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (args->argv[0], &if_.eip, &if_.esp);

  /* Relay load status to parent. */
  cur->child_info->load_success = success;
  sema_up (&cur->child_info->load_sema);

  /* If load failed, quit. */
  if (!success) 
    {
      palloc_free_page (args->argv[0]);
      free (args->argv);
      free (args);
      thread_exit ();
    }

  /* Setup stack with arguments. */
  setup_stack_args (args->argc, args->argv, &if_.esp);

  palloc_free_page (args->argv[0]);
  free (args->argv);
  free (args);

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status. 
 * If it was terminated by the kernel (i.e. killed due to an exception), 
 * returns -1.  
 * If TID is invalid or if it was not a child of the calling process, or if 
 * process_wait() has already been successfully called for the given TID, 
 * returns -1 immediately, without waiting. */
int
process_wait (tid_t child_tid) 
{
  struct child_info i;
  i.child_pid = (pid_t) child_tid;
  struct hash_elem *e = hash_find (&thread_current ()->children_map, &i.elem);

  /* Current thread does not have child to wait for with tid child_tid. */
  if (e == NULL)
    {
      return -1;
    }

  struct child_info *child_info = hash_entry (e, struct child_info, elem);
  
  /* Wait for child to exit. */
  sema_down (&child_info->exit_sema);

  /* Must ensure child is not still holding exists_lock before freeing
     child_info struct. */
  lock_acquire (&child_info->exists_lock);
  lock_release (&child_info->exists_lock);

  int status = child_info->status;
  
  /* Remove child_info from parent's hashmap as waiting only allowed once. 
     Since child has exited, this parent thread can safely free child_info. */
  hash_delete (&thread_current ()->children_map, &child_info->elem);
  free (child_info);

  return status;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();

  /* Print termination message. */
  printf ("%s: exit(%d)\n", cur->name, cur->child_info->status);

  bool should_free = false;

  lock_acquire (&cur->child_info->exists_lock);  
  /* Inform parent thread that this process has exited. */
  if (cur->child_info->parent_exists)
    {
      /* Indicate to parent that child has exited. */
      cur->child_info->child_exists = false;
      sema_up (&cur->child_info->exit_sema);
    }
  /* If both parent and child have died, should free child_info struct. */
  else
    {
      should_free = true;
    }
  lock_release (&cur->child_info->exists_lock);

  /* We do not have to worry about the parent thread accessing child_info
     struct after free because it is necessarily dead (or won't access the
     child_info struct again at least). */ 
  if (should_free)
    {
      free (cur->child_info);
    }

  /* Destroy this thread's children_map and all child_info structs related
     to children of this thread. */
  hash_destroy (&cur->children_map, child_info_destroy);

  /* Destroy this thread's fd_file_map and all fd_file structs related
     to the open files of this thread. */
  lock_acquire (&filesys_lock);
  hash_destroy (&cur->fd_file_map, fd_file_destroy);
  lock_release (&filesys_lock);

  lock_acquire (&shared_pages_lock);

  /* Hold frame table lock while clearing up spt and frame table to 
     ensure an intermediate state cannot be seen. */
  lock_acquire (&frame_table_lock);

  /* Free all supplemental page table entries and associated resources. */
  lock_acquire (&cur->spt_lock);
  lock_acquire (&cur->io_lock);
  hash_destroy (&cur->supp_page_table, destroy_spte);
  lock_release (&cur->io_lock);
  lock_release (&cur->spt_lock);
  
  lock_release (&shared_pages_lock);
  
  /* Unmap all memory-mapped files. */
  hash_destroy (&cur->mmap_table, mmap_file_destroy);

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  uint32_t *pd;
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
  
  lock_release (&frame_table_lock);

  /* Allow write access and close the executable file */
  if (cur->executable != NULL)
    {
      lock_acquire (&filesys_lock);
      file_allow_write (cur->executable);
      file_close (cur->executable);
      lock_release (&filesys_lock);
      cur->executable = NULL;
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* Open executable file. */
  lock_acquire (&filesys_lock);
  file = filesys_open (file_name);
  if (file == NULL) 
    {
      lock_release (&filesys_lock);
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }
  /* Deny writing to executable file while process is running. */
  file_deny_write (file);
  t->executable = file;

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      lock_release (&filesys_lock);
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }
  lock_release (&filesys_lock);

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      lock_acquire (&filesys_lock);
      if (file_ofs < 0 || file_ofs > file_length (file))
        {
          lock_release (&filesys_lock);
          goto done;
        }
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        {
          lock_release (&filesys_lock);
          goto done;
        }
      lock_release (&filesys_lock);
      
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  lock_acquire (&filesys_lock);
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    {
      lock_release (&filesys_lock);
      return false;
    }
  lock_release (&filesys_lock);

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  lock_acquire (&filesys_lock);
  file_seek (file, ofs);
  lock_release (&filesys_lock);
  uint32_t curr_ofs = ofs;
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;
      
      struct thread *t = thread_current ();
      
      struct spt_entry entry;
      entry.user_page = upage;

      struct hash_elem *e = hash_find (&t->supp_page_table, &entry.elem);

      if (e == NULL)
        {
          /* Add entry for upage in supplemental page table. */
          struct spt_entry *spte = malloc (sizeof (struct spt_entry));
          if (spte == NULL)
            {
              return false;
            }

          spte->is_pinned = false;
          spte->in_memory = false;
          spte->user_page = upage;
          spte->page_type = EXEC_FILE;
          spte->in_swap = false;
          spte->file = file;
          spte->file_ofs = curr_ofs; 
          spte->page_read_bytes = page_read_bytes;
          spte->page_zero_bytes = page_zero_bytes;
          spte->writable = writable;

          hash_insert (&t->supp_page_table, &spte->elem);
        }
      else
        {
          struct spt_entry *spte = hash_entry (e, struct spt_entry, elem);
          if (writable && !spte->writable)
            {
              spte->writable = true;
            }
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
      curr_ofs += page_read_bytes;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp) 
{
  uint8_t *kpage;
  bool success = false;

  kpage = get_frame (PAL_USER | PAL_ZERO);
  if (kpage != NULL) 
    {
      void *upage = ((uint8_t *) PHYS_BASE) - PGSIZE;
      success = install_page (upage, kpage, true);
      if (success)
        {
          *esp = PHYS_BASE;

          struct thread *t = thread_current ();

          /* Add entry for upage in supplemental page table. */
          struct spt_entry *spte = malloc (sizeof (struct spt_entry));
          if (spte == NULL)
            {
              return false;
            }

          spte->in_memory = true;
          spte->is_pinned = false;
          spte->user_page = upage;
          spte->page_type = STACK;
          spte->in_swap = false;
          spte->writable = true;
          spte->kpage = kpage;

          lock_acquire (&t->spt_lock);
          hash_insert (&t->supp_page_table, &spte->elem);         
          lock_release (&t->spt_lock);
        }
      else
        {
          lock_acquire (&frame_table_lock);
          free_frame (kpage);
          lock_release (&frame_table_lock);
        }
    }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();
  
  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}