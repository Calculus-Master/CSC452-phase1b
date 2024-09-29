#ifndef CSC452_PHASE1B_QUEUE_H
#define CSC452_PHASE1B_QUEUE_H

#include <phase1.h>

#define QUEUE_SIZE (MAXPROC + 2)

typedef struct Queue {
    int queue[QUEUE_SIZE];
    int start;
    int end;
} Queue;

extern void queueInit(Queue* q);

extern void queueAdd(Queue* q, int pid);

extern int queueRemove(Queue* q);

extern int queueEmpty(Queue* q);

extern void queueDebug(Queue* q);

#endif
