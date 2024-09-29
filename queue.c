#include <queue.h>
#include <string.h>
#include <stdio.h>

void queueInit(Queue* q)
{
    memset(q->queue, 0, sizeof(Queue));
}

void queueAdd(Queue* q, int pid)
{
    int target = queueEmpty(q) ? q->end : (q->end + 1) % QUEUE_SIZE;
    q->queue[target] = pid;
    q->end = target;
}

int queueRemove(Queue* q)
{
    int ret = q->queue[q->start];
    q->queue[q->start] = 0;

    if(q->start != q->end)
        q->start = (q->start + 1) % QUEUE_SIZE;

    return ret;
}

int queueEmpty(Queue* q)
{
    return q->start == q->end && q->queue[q->start] == 0;
}

void queueDebug(Queue* q)
{
    USLOSS_Console("Printing Queue: (%d -> %d) [ ", q->start, q->end);
    for (int i = 0; i < QUEUE_SIZE; i++)
    {
        USLOSS_Console("%d ", q->queue[i]);
    }
    USLOSS_Console("]\n");
}
