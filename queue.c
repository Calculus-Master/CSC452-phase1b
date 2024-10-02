#include <queue.h>
#include <string.h>
#include <stdio.h>

// Initializes a queue by setting all elements to zero
// q: Pointer to the Queue structure to be initialized
void queueInit(Queue* q)
{
    memset(q->queue, 0, sizeof(Queue));
}

// Adds a process ID to the end of the queue
// q: Pointer to the Queue structure
// pid: Process ID to be added
void queueAdd(Queue* q, int pid)
{
    int target = queueEmpty(q) ? q->end : (q->end + 1) % QUEUE_SIZE;
    q->queue[target] = pid;
    q->end = target;
}

// Removes and returns the first process ID from the queue
// q: Pointer to the Queue structure
// Returns: The process ID removed from the queue
int queueRemove(Queue* q)
{
    int ret = q->queue[q->start];
    q->queue[q->start] = 0;

    if(q->start != q->end)
        q->start = (q->start + 1) % QUEUE_SIZE;

    return ret;
}

// Checks if the queue is empty
// q: Pointer to the Queue structure
// Returns: 1 if empty, 0 otherwise
int queueEmpty(Queue* q)
{
    return q->start == q->end && q->queue[q->start] == 0;
}

// Prints the contents of the queue for debugging
// q: Pointer to the Queue structure
void queueDebug(Queue* q)
{
    USLOSS_Console("Printing Queue: (%d -> %d) [ ", q->start, q->end);
    for (int i = 0; i < QUEUE_SIZE; i++)
    {
        USLOSS_Console("%d ", q->queue[i]);
    }
    USLOSS_Console("]\n");
}
