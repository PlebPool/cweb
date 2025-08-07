//
// Created by mawe on 7/24/25.
//

#include <errno.h>
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <wthread.h>
#include <sys/syslog.h>

threadpool_t* threadpool_create(int thread_count) {
    if (thread_count <= 0 || thread_count > MAX_THREADS) {
        syslog(LOG_ERR, "Invalid argument [thread_count] = %i", thread_count);
        return NULL;
    }

    threadpool_t *pool = malloc(sizeof(threadpool_t));
    if (pool == NULL) {
        syslog(LOG_ERR, "Failed to allocate memory for thread pool.");
        return NULL;
    }

    // Initialize pool
    pool->thread_count = thread_count;
    pool->queue_size = 0;
    pool->shutdown = 0;
    pool->queue_head = NULL;
    pool->queue_tail = NULL;

    // Allocate memory for threads
    pool->threads = malloc(sizeof(pthread_t) * thread_count);
    if (pool->threads == NULL) {
        syslog(LOG_ERR, "Failed to allocate memory for thread array.");
        free(pool);
        return NULL;
    }

    // Initialize mutex and condition variable
    if (pthread_mutex_init(&pool->lock, NULL) != 0 ||
        pthread_cond_init(&pool->work_available, NULL) != 0) {
        syslog(LOG_ERR, "Error initializing thread mutex and/or condition.");
        free(pool->threads);
        free(pool);
        return NULL;
    }

    // Create worker threads
    for (int i = 0; i < thread_count; i++) {
        if (pthread_create(&pool->threads[i], NULL, threadpool_worker, pool) != 0) {
            syslog(LOG_ERR, "Failed to create thread %i.", i);
            threadpool_destroy(pool);
            return NULL;
        }
    }

    syslog(LOG_INFO, "Thread pool created with %i threads.", thread_count);
    return pool;
}

int threadpool_add_task(threadpool_t *pool, void (*function)(void *), void *arg) {
    if (pool == NULL || function == NULL) {
        syslog(LOG_ERR, "Invalid argument [pool] = %p, [function] = %p", pool, function);
        return -1;
    }

    pthread_mutex_lock(&pool->lock);

    if (pool->shutdown) {
        syslog(LOG_ERR, "Error adding task: Pool shutdown triggered.");
        pthread_mutex_unlock(&pool->lock);
        return -1;
    }

    if (pool->queue_size >= MAX_QUEUE) {
        syslog(LOG_ERR, "Error adding task: Task queue full...");
        pthread_mutex_unlock(&pool->lock);
        return -1;
    }

    // Create new task
    task_t *task = malloc(sizeof(task_t));
    if (task == NULL) {
        syslog(LOG_ERR, "Error adding task: Failed to allocate memory for task.");
        pthread_mutex_unlock(&pool->lock);
        return -1;
    }

    task->function = function;
    task->arg = arg;
    task->next = NULL;

    // Add task to queue
    if (pool->queue_head == NULL) {
        pool->queue_head = task;
        pool->queue_tail = task;
    } else {
        pool->queue_tail->next = task;
        pool->queue_tail = task;
    }

    pool->queue_size++;

    // Signal a waiting thread
    pthread_cond_signal(&pool->work_available);
    pthread_mutex_unlock(&pool->lock);

    return 0;
}

// Worker loop
static void* threadpool_worker(void *arg) {
    threadpool_t *pool = (threadpool_t *)arg;
    task_t *task;

    while (1) {
        pthread_mutex_lock(&pool->lock);

        // Wait for a task or shutdown signal
        while (pool->queue_size == 0 && !pool->shutdown) {
            pthread_cond_wait(&pool->work_available, &pool->lock);
        }

        if (pool->shutdown) {
            syslog(LOG_INFO, "Threadpool shutdown triggered.");
            pthread_mutex_unlock(&pool->lock);
            pthread_exit(NULL);
        }

        // Get task from queue
        task = pool->queue_head;
        if (task != NULL) {
            pool->queue_head = task->next;
            if (pool->queue_head == NULL) {
                pool->queue_tail = NULL;
            }
            pool->queue_size--;
        }

        pthread_mutex_unlock(&pool->lock);

        // Execute task
        if (task != NULL) {
            task->function(task->arg);
            free(task);
        }
    }

    return NULL;
}

int threadpool_destroy(threadpool_t *pool) {
    if (pool == NULL) {
        return -1;
    }

    pthread_mutex_lock(&pool->lock);
    pool->shutdown = 1;
    pthread_cond_broadcast(&pool->work_available); // Will trigger check of shutdown signal.
    pthread_mutex_unlock(&pool->lock);

    // Wait for all threads to finish
    for (int i = 0; i < pool->thread_count; i++) {
        pthread_join(pool->threads[i], NULL);
    }

    // Clean up remaining tasks
    while (pool->queue_head != NULL) {
        task_t *task = pool->queue_head;
        pool->queue_head = task->next;
        free(task);
    }

    // Clean up resources
    pthread_mutex_destroy(&pool->lock);
    pthread_cond_destroy(&pool->work_available);
    free(pool->threads);
    free(pool);

    syslog(LOG_INFO, "Thread pool destroyed.");

    return 0;
}

