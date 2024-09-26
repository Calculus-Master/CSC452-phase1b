#include <phase1.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define READY_STATE 0
#define RUNNING_STATE 1
#define TERMINATED_STATE 2

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

    TEMP_switchTo(pid);

    return 0;
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

    memset(process_table, 0, sizeof(process_table));

    current_process = &process_table[next_pid % MAXPROC];
    current_process->pid = next_pid++;
    current_process->priority = 6;
    current_process->state = READY_STATE;
    strcpy(current_process->name, "init");

    current_process->stack = init_stack;

    current_process->func = do_init;
    current_process->arg = NULL;

    USLOSS_ContextInit(&(current_process->context), init_stack, USLOSS_MIN_STACK, NULL, process_wrapper);

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

void TEMP_switchTo(int pid)
{
    check_kernel_mode(TEMP_SWITCH_TO_NAME);

    int old_psr = disable_interrupts();

    Process *old = current_process;
    current_process = &process_table[pid % MAXPROC];

    // Update states
    if (pid != 1 && old->state != TERMINATED_STATE)
        old->state = READY_STATE;
    current_process->state = RUNNING_STATE;

    USLOSS_ContextSwitch(pid == 1 ? NULL : &(old->context), &(current_process->context));

    // Restore interrupts
    USLOSS_PsrSet(old_psr);
}