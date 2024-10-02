#include <phase1.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <queue.h>

#define READY_STATE 0
#define RUNNING_STATE 1
#define TERMINATED_STATE 2
#define BLOCKED_STATE 3

typedef struct Process
{
    int pid;
    int priority;
    int status;
    int state; // info on the running/block state of each process
    char name[MAXNAME];
    char *stack;

    int (*func)(void *);
    void *arg;

    // structs to set up linked lists of the processes
    struct Process *parent;
    struct Process *next_sibling;
    struct Process *children;

    int start_time;
    short join_waiting;
    struct Process *zapped;

    USLOSS_Context context;
} Process;

Process process_table[MAXPROC];
Process *current_process;
int next_pid = 1;
char init_stack[USLOSS_MIN_STACK];

// Run queues for each priority
Queue run_queue_p1;
Queue run_queue_p2;
Queue run_queue_p3;
Queue run_queue_p4;
Queue run_queue_p5;
Queue run_queue_p6;

Queue* p1 = &run_queue_p1;
Queue* p2 = &run_queue_p2;
Queue* p3 = &run_queue_p3;
Queue* p4 = &run_queue_p4;
Queue* p5 = &run_queue_p5;
Queue* p6 = &run_queue_p6;

// Process functions and helper methods
int do_testcase_main()
{
    int ret = testcase_main();

    if(ret != 0)
        USLOSS_Console("ERROR: testcase_main() returned a non-zero value: %d\n", ret);

    USLOSS_Halt(0);

    return 0;
}

int do_init()
{
    phase2_start_service_processes();
    phase3_start_service_processes();
    phase4_start_service_processes();
    phase5_start_service_processes();

    // Spawn the testcase_main process
    spork("testcase_main", do_testcase_main, NULL, USLOSS_MIN_STACK, 3);

    // Join the testcase_main process
    int join_ret = 0;
    int join_status; // Value is always ignored
    while(join_ret != -2)
        join_ret = join(&join_status);

    USLOSS_Halt(0);

    return 0; // Should never happen
}

// Wrapper function to call the process's function and then quit
void process_wrapper()
{
    USLOSS_PsrSet(USLOSS_PsrGet() | USLOSS_PSR_CURRENT_INT);
    int status = current_process->func(current_process->arg);
    quit(status);
}

// Checks if the current process is in kernel mode
void check_kernel_mode(const char *function_name)
{
    if ((USLOSS_PsrGet() & USLOSS_PSR_CURRENT_MODE) == 0)
    {
        USLOSS_Console("ERROR: Someone attempted to call %s while in user mode!\n", function_name);
        USLOSS_Halt(1);
    }
}

// Disables interrupts by saving the current PSR and setting it to not interrupt
int disable_interrupts()
{
    int old_psr = USLOSS_PsrGet();
    USLOSS_PsrSet(USLOSS_PsrGet() & ~USLOSS_PSR_CURRENT_INT);
    return old_psr;
}

// Adds the process to the appropriate run queue based on its priority
void add_process_to_queue(Process* process)
{
    switch(process->priority)
    {
        case 1:
            queueAdd(p1, process->pid);
            break;
        case 2:
            queueAdd(p2, process->pid);
            break;
        case 3:
            queueAdd(p3, process->pid);
            break;
        case 4:
            queueAdd(p4, process->pid);
            break;
        case 5:
            queueAdd(p5, process->pid);
            break;
        case 6:
            queueAdd(p6, process->pid);
            break;
        default:
            break;
    }
}

// Main phase 1 functions
void phase1_init(void)
{
    check_kernel_mode(__func__);

    int old_psr = disable_interrupts();

    // Set up the process table
    memset(process_table, 0, sizeof(process_table));

    // Create the init process
    Process* init_process = &process_table[next_pid % MAXPROC];
    init_process->pid = next_pid++;
    init_process->priority = 6;
    init_process->state = READY_STATE;
    strcpy(init_process->name, "init");

    init_process->stack = init_stack;

    init_process->func = do_init;
    init_process->arg = NULL;

    USLOSS_ContextInit(&(init_process->context), init_stack, USLOSS_MIN_STACK, NULL, process_wrapper);

    // Set current process pointer to NULL to help dispatcher
    current_process = NULL;

    // Initialize the run queues
    queueInit(p1);
    queueInit(p2);
    queueInit(p3);
    queueInit(p4);
    queueInit(p5);
    queueInit(p6);

    // Restore interrupts
    USLOSS_PsrSet(old_psr);
}

// Spawns a new process with the given parameters
int spork(char *name, int (*func)(void *), void *arg, int stacksize, int priority)
{
    check_kernel_mode(__func__);

    int old_psr = disable_interrupts();

    // Check parameters
    if (stacksize < USLOSS_MIN_STACK)
        return -2; // Stack size too small
    else if (name == NULL || func == NULL)
        return -1; // Name or function is NULL
    else if (strlen(name) > MAXNAME)
        return -1; // Name too long
    else if (priority < 1 || priority > 6)
        return -1; // Priority out of range

    // Cycle through available slots to find a free one
    // Free: PID 0 or the state is TERMINATED_STATE
    int first_slot = next_pid % MAXPROC;
    Process *new_process = &process_table[next_pid % MAXPROC];
    while (new_process->pid != 0)
    {
        next_pid++;
        if (next_pid % MAXPROC == first_slot)
            return -1; // No free slots

        new_process = &process_table[next_pid % MAXPROC];
    }

    // Initialize the new process
    memset(new_process, 0, sizeof(Process));
    new_process->pid = next_pid++;
    new_process->state = READY_STATE;
    new_process->priority = priority;
    strcpy(new_process->name, name);

    new_process->stack = malloc(stacksize);
    new_process->func = func;
    new_process->arg = arg;

    USLOSS_ContextInit(&(new_process->context), new_process->stack, stacksize, NULL, process_wrapper);

    // Set up the parent-child relationship
    new_process->parent = current_process;
    new_process->next_sibling = current_process->children;
    current_process->children = new_process;
    current_process->zapped = NULL;

    // Add the new process to the appropriate run queue
    add_process_to_queue(new_process);

    // Call the dispatcher to start the new process
    dispatcher();

    // Restore interrupts
    USLOSS_PsrSet(old_psr);

    // Return the PID of the new process
    return new_process->pid;
}

// Joins on a child process and returns its status
int join(int *status)
{
    check_kernel_mode(__func__);

    int old_psr = disable_interrupts();

    // if status pointer is null, return -3
    if (status == NULL)
        return -3;

    // if the process does not have any children return -2
    if (current_process->children == NULL)
        return -2;
    
    Process *child = current_process->children;
    while (child != NULL) {
        if (child->state == TERMINATED_STATE) {
            // Store the status through the out-pointer
            *status = child->status;

            // Remove the child from the parent's list
            if (child == current_process->children) {
                current_process->children = child->next_sibling;
            } else {
                Process *prev = current_process->children;
                while (prev->next_sibling != child) {
                    prev = prev->next_sibling;
                }
                prev->next_sibling = child->next_sibling;
            }

            // Free the child's stack memory
            if (child->stack != NULL) {
                free(child->stack);
                child->stack = NULL;
            }

            // Store the child's PID before clearing the process table entry
            int child_pid = child->pid;
            memset(child, 0, sizeof(Process));

            // Unblock the parent if it is in join_wait_state
            if (current_process->state == BLOCKED_STATE && current_process->join_waiting) {
                current_process->state = READY_STATE;
                current_process->join_waiting = 0;
                add_process_to_queue(current_process);
            }

            // Restore interrupts before returning
            USLOSS_PsrSet(old_psr);
            return child_pid;
        }
        child = child->next_sibling;
    }

    USLOSS_PsrSet(old_psr);

    // If no children have terminated, block the current process
    current_process->state = BLOCKED_STATE;
    current_process->join_waiting = 1;
    dispatcher();

    // recall join after so that when it's waken up after a child terminates, it can return the status of the child that just terminated
    return join(status);
}

// Quits the current process with the given status
void quit(int status)
{
    check_kernel_mode(__func__);
    int old_psr = disable_interrupts();

    // Check if the current process has any children
    if (current_process->children != NULL)
    {
        USLOSS_Console("ERROR: Process pid %d called quit() while it still had children.\n", current_process->pid);
        USLOSS_Halt(1);
    }

    // Status for this process stored in the process table entry
    current_process->status = status;
    current_process->state = TERMINATED_STATE;

    // Unblock the parent if it is in join_wait_state
    if (current_process->parent->state == BLOCKED_STATE && current_process->parent->join_waiting) {
        current_process->parent->state = READY_STATE;
        current_process->parent->join_waiting = 0;
        add_process_to_queue(current_process->parent);
    }

    // Unblock any processes that are zapped and waiting for this process
    for(int i = MAXPROC - 1; i >= 0; i--)
    {
        Process* p = &process_table[i];
        if(p->pid != 0 && p->zapped != NULL && p->zapped->pid == current_process->pid)
        {
            p->zapped = NULL;
            p->state = READY_STATE;
            add_process_to_queue(p);
        }
    }

    // Call the dispatcher to start the next process
    dispatcher();

    // Restore interrupts
    USLOSS_PsrSet(old_psr);
}

// Zaps a process by setting a flag in the current process
void zap(int pid)
{
    check_kernel_mode(__func__);
    int old_psr = disable_interrupts();

    // Check if the caller is trying to zap itself
    if (pid == current_process->pid) {
        USLOSS_Console("ERROR: Attempt to zap() itself.\n");
        USLOSS_Halt(1);
    }

    // Check if the target process exists and is not terminated
    Process* target = &process_table[pid % MAXPROC];

    if(target->pid != pid) {
        USLOSS_Console("ERROR: Attempt to zap() a non-existent process.\n");
        USLOSS_Halt(1);
    }

    // Check if the target is already in the process of dying
    if (target->pid != pid || target->state == TERMINATED_STATE) {
        USLOSS_Console("ERROR: Attempt to zap() a process that is already in the process of dying.\n");
        USLOSS_Halt(1);
    }

    // Check if the target is the init process (PID 1)
    if (pid == 1) {
        USLOSS_Console("ERROR: Attempt to zap() init.\n");
        USLOSS_Halt(1);
    }

    // Update a flag in the current process to indicate what it's zapping
    current_process->zapped = target;

    blockMe();

    // Restore interrupts
    USLOSS_PsrSet(old_psr);
}

void blockMe(void)
{
    check_kernel_mode(__func__);

    int old_psr = disable_interrupts();

    current_process->state = BLOCKED_STATE;
    dispatcher();

    // Restore interrupts
    USLOSS_PsrSet(old_psr);
}

int unblockProc(int pid)
{
    check_kernel_mode(__func__);

    int old_psr = disable_interrupts();

    // Check if the process exists and is blocked
    Process* proc = &process_table[pid % MAXPROC];

    if(proc->pid == 0 || proc->state != BLOCKED_STATE)
        return -2;

    proc->state = READY_STATE;
    add_process_to_queue(proc);
    dispatcher();

    // Restore interrupts
    USLOSS_PsrSet(old_psr);

    return 0;
}

void dispatcher(void)
{
    check_kernel_mode(__func__);

    int old_psr = disable_interrupts();

    // Edge case to start the very first init process
    if(current_process == NULL)
    {
        current_process = &process_table[1];
        current_process->state = RUNNING_STATE;
        USLOSS_ContextSwitch(NULL, &(current_process->context));
    }
    else // Regular dispatcher logic
    {
        // If either of these are true, don't check priorities when pulling from queues
        int override = current_process->state == BLOCKED_STATE || current_process->state == TERMINATED_STATE || (currentTime() - current_process->start_time) / 1000 > 80;

        int target_pid = -1;

        // Check each priority queue in order and pull the PID of the process to run
        if(!queueEmpty(p1) && (override || current_process->priority > 1))
            target_pid = queueRemove(p1);
        else if(!queueEmpty(p2) && (override || current_process->priority > 2))
            target_pid = queueRemove(p2);
        else if(!queueEmpty(p3) && (override || current_process->priority > 3))
            target_pid = queueRemove(p3);
        else if(!queueEmpty(p4) && (override || current_process->priority > 4))
            target_pid = queueRemove(p4);
        else if(!queueEmpty(p5) && (override || current_process->priority > 5))
            target_pid = queueRemove(p5);
        else if(!queueEmpty(p6) && (override || current_process->priority > 6))
            target_pid = queueRemove(p6);

        // If a process was found to run, switch to it
        if(target_pid != -1)
        {
            Process* target = &process_table[target_pid % MAXPROC];

            Process* old = current_process;
            current_process = target;
            current_process->state = RUNNING_STATE;

            if(old->state == RUNNING_STATE)
            {
                old->state = READY_STATE;
                add_process_to_queue(old);
            }

            current_process->start_time = currentTime();
            USLOSS_ContextSwitch(&(old->context), &(current_process->context));
        }
    }

    // Restore interrupts
    USLOSS_PsrSet(old_psr);
}

int getpid(void)
{
    return current_process->pid;
}

// Dumps the state of all processes 
void dumpProcesses(void)
{
    check_kernel_mode(__func__);

    int old_psr = disable_interrupts();

    USLOSS_Console(" PID  PPID  NAME              PRIORITY  STATE\n");

    for (int i = 0; i < MAXPROC; i++)
    {
        Process *proc = &process_table[i];
        if (proc->pid != 0)
        {
            char state[40];
            switch (proc->state)
            {
                case READY_STATE:
                    strcpy(state, "Runnable");
                    break;
                case RUNNING_STATE:
                    strcpy(state, "Running");
                    break;
                case TERMINATED_STATE:
                    sprintf(state, "Terminated(%d)", proc->status);
                    break;
                case BLOCKED_STATE:
                    strcpy(state, proc->zapped != NULL ? "Blocked(waiting for zap target to quit)" : proc->join_waiting ? "Blocked(waiting for child to quit)" : "Blocked(3)");
                    break;
                default:
                    strcpy(state, "Unknown");
            }

            USLOSS_Console(" %3d %5d  %-16s  %d         %s\n",
                           proc->pid,
                           proc->parent ? proc->parent->pid : 0,
                           proc->name,
                           proc->priority,
                           state);
        }
    }

    // Restore interrupts
    USLOSS_PsrSet(old_psr);
}