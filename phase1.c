#include <phase1.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <queue.h>

#define READY_STATE 0
#define RUNNING_STATE 1
#define TERMINATED_STATE 2
#define BLOCKED_STATE 3

// Function name definitions
#define PHASE1_INIT_NAME "phase1_init"
#define SPORK_NAME "spork"
#define JOIN_NAME "join"
#define QUIT_NAME "quit_phase_1a"
#define DUMP_PROCESSES_NAME "dumpProcesses"
#define TEMP_SWITCH_TO_NAME "TEMP_switchTo"

typedef struct Process
{
    int pid;
    int priority;
    int status;
    int state;
    char name[MAXNAME];
    char *stack;

    int (*func)(void *);
    void *arg;

    struct Process *parent;
    struct Process *next_sibling;
    struct Process *children;

    USLOSS_Context context;
} Process;

Process process_table[MAXPROC];
Process *current_process;
int next_pid = 1;
char init_stack[USLOSS_MIN_STACK];

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

// Process functions
int do_testcase_main()
{
    testcase_main();

    USLOSS_Console("Phase 1A TEMPORARY HACK: testcase_main() returned, simulation will now halt.\n");
    USLOSS_Halt(0);

    return 0;
}

int do_init()
{
    phase2_start_service_processes();
    phase3_start_service_processes();
    phase4_start_service_processes();
    phase5_start_service_processes();

    USLOSS_Console("Phase 1A TEMPORARY HACK: init() manually switching to testcase_main() after using spork() to create it.\n");

    int pid = spork("testcase_main", do_testcase_main, NULL, USLOSS_MIN_STACK, 3);

    int join_ret = 0;
    int join_status; // Value is always ignored
    while(join_ret != -2)
        join_ret = join(&join_status);

    USLOSS_Halt(0);

    return 0; // Should never happen
}

void process_wrapper()
{
    USLOSS_PsrSet(USLOSS_PsrGet() | USLOSS_PSR_CURRENT_INT);
    int status = current_process->func(current_process->arg);
    quit_phase_1a(status, current_process->parent->pid);
}

void check_kernel_mode(const char *function_name)
{
    if ((USLOSS_PsrGet() & USLOSS_PSR_CURRENT_MODE) == 0)
    {
        USLOSS_Console("ERROR: Someone attempted to call %s while in user mode!\n", function_name);
        USLOSS_Halt(1);
    }
}

int disable_interrupts()
{
    int old_psr = USLOSS_PsrGet();
    USLOSS_PsrSet(USLOSS_PsrGet() & ~USLOSS_PSR_CURRENT_INT);
    return old_psr;
}

// Main phase 1 functions
void phase1_init(void)
{
    check_kernel_mode(PHASE1_INIT_NAME);

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

int spork(char *name, int (*func)(void *), void *arg, int stacksize, int priority)
{
    check_kernel_mode(SPORK_NAME);

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

    memset(new_process, 0, sizeof(Process));
    new_process->pid = next_pid++;
    new_process->state = READY_STATE;
    new_process->priority = priority;
    strcpy(new_process->name, name);

    new_process->stack = malloc(stacksize);
    new_process->func = func;
    new_process->arg = arg;

    USLOSS_ContextInit(&(new_process->context), new_process->stack, stacksize, NULL, process_wrapper);

    new_process->parent = current_process;
    new_process->next_sibling = current_process->children;
    current_process->children = new_process;

    // Restore interrupts
    USLOSS_PsrSet(old_psr);
    return new_process->pid;
}

int join(int *status)
{
    check_kernel_mode(JOIN_NAME);

    int old_psr = disable_interrupts();

    // if status pointer is null, return -3
    if (status == NULL)
        return -3;

    // if the process does not have any children return -2
    if (current_process->children == NULL)
        return -2;

    // Iterate through children to find any dead processes
    Process *child = current_process->children;
    while (child != NULL)
    {
        if (child->state == TERMINATED_STATE)
        {
            // Store the status through the out-pointer
            *status = child->status;

            // Remove the child from the parent's list
            if (child == current_process->children)
            {
                current_process->children = child->next_sibling;
            }
            else
            {
                Process *prev = current_process->children;
                while (prev->next_sibling != child)
                {
                    prev = prev->next_sibling;
                }
                prev->next_sibling = child->next_sibling;
            }

            // Free the child's stack memory
            if (child->stack != NULL)
            {
                free(child->stack);
                child->stack = NULL;
            }

            // Return the child's PID and clear out the child's process table entry
            int child_pid = child->pid;
            memset(child, 0, sizeof(Process));
            return child_pid;
        }
        child = child->next_sibling;
    }

    // Restore interrupts
    USLOSS_PsrSet(old_psr);
}

//TODO: Remove and replace with quit
void quit_phase_1a(int status, int switchToPid)
{
    check_kernel_mode(QUIT_NAME);

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

    TEMP_switchTo(switchToPid);

    // Restore interrupts
    USLOSS_PsrSet(old_psr);
}

void quit(int status)
{
    // Not needed for Phase 1a
}

void zap(int pid)
{

}

void blockMe(void)
{

}

int unblockProc(int pid)
{

}

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

void dispatcher(void)
{
    check_kernel_mode(DUMP_PROCESSES_NAME);

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
        int target_pid = -1;

        if(!queueEmpty(p1))
            target_pid = queueRemove(p1);
        else if(!queueEmpty(p2))
            target_pid = queueRemove(p2);
        else if(!queueEmpty(p3))
            target_pid = queueRemove(p3);
        else if(!queueEmpty(p4))
            target_pid = queueRemove(p4);
        else if(!queueEmpty(p5))
            target_pid = queueRemove(p5);
        else if(!queueEmpty(p6))
            target_pid = queueRemove(p6);

        if(target_pid != -1)
        {
            Process* old = current_process;
            old->state = READY_STATE;

            current_process = &process_table[target_pid % MAXPROC];
            current_process->state = RUNNING_STATE;

            add_process_to_queue(old);

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

void dumpProcesses(void)
{
    check_kernel_mode(DUMP_PROCESSES_NAME);

    int old_psr = disable_interrupts();

    USLOSS_Console(" PID  PPID  NAME              PRIORITY  STATE\n");

    for (int i = 0; i < MAXPROC; i++)
    {
        Process *proc = &process_table[i];
        if (proc->pid != 0)
        {
            char state[20];
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

//TODO: Remove and replace with dispatcher
//void TEMP_switchTo(int pid)
//{
//    check_kernel_mode(TEMP_SWITCH_TO_NAME);
//
//    int old_psr = disable_interrupts();
//
//    Process *old = current_process;
//    current_process = &process_table[pid % MAXPROC];
//
//    // Update states
//    if (pid != 1 && old->state != TERMINATED_STATE)
//        old->state = READY_STATE;
//    current_process->state = RUNNING_STATE;
//
//    USLOSS_ContextSwitch(pid == 1 ? NULL : &(old->context), &(current_process->context));
//
//    // Restore interrupts
//    USLOSS_PsrSet(old_psr);
//}