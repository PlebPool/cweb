//
// Created by mawe on 7/24/25.
//

#ifndef WTHREAD_H
#define WTHREAD_H
#include <bits/pthreadtypes.h>

#define MAX_THREADS 10
#define MAX_QUEUE 256

// Task structure
typedef struct task {
    void (*function)(void *arg);
    void *arg;
    struct task *next;
} task_t;

// Thread pool structure
typedef struct {
    pthread_mutex_t lock;
    pthread_cond_t work_available;
    pthread_t *threads;
    task_t *queue_head;
    task_t *queue_tail;
    int thread_count;
    int queue_size;
    int shutdown;
} threadpool_t;

// Function prototypes
threadpool_t* threadpool_create(int thread_count);
int threadpool_add_task(threadpool_t *pool, void (*function)(void *), void *arg);
int threadpool_destroy(threadpool_t *pool);
static void* threadpool_worker(void *arg);


#endif //WTHREAD_H
