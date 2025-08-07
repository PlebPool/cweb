//
// Created by mawe on 7/23/25.
//
#include "server.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/limits.h>

#include "cstring.h"
#include <unistd.h>
#include <syslog.h>

#include "wsocket.h"
#include <sys/epoll.h>
#include <sys/socket.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>

#include "wthread.h"

threadpool_t *threadpool;

pthread_t server_thread;
int exit_flag = 0;

void thread_close_fd(void* fd) {
    close(*(int*) fd);
}

void sig_handler(int signo) {
    syslog(LOG_INFO, "Received signal %d", signo);
    exit_flag = 1;
}

void print_file(const char* filename) {
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s", filename);
    FILE *fp = fopen(path, "r");

    if (fp == NULL) {
        syslog(LOG_ERR, "cannot open file %s: %s", path, strerror(errno));
        return;
    }

    int ch;
    while ((ch = fgetc(fp)) != EOF) {
        printf("%c", ch);
    }

    fclose(fp);
}

int server_init(server_t* server) {
    return 0;
}

void server_destroy(const server_t* server) {
    cstring_destroy(server->ascii_art_path);
    server = NULL;
}

int server_set_port(server_t* server, unsigned short port) {
    server->port = port;
    return 0;
}

int server_set_ascii_art(server_t* server, const cstring_t* ascii_art_path) {
    cstring_t* string = malloc(sizeof(cstring_t));
    string->buffer = malloc(ascii_art_path->size);
    memcpy(string->buffer, ascii_art_path->buffer, ascii_art_path->size);
    server->ascii_art_path = string;
    return 0;
}

int server_set_static_resource(server_t* server, const cstring_t* static_resource_path) {
    return 0;
}

int server_set_opt(server_t* server, const int s_o_opt, void* s_o_arg) {
    switch (s_o_opt) {
        case S_O_PORT:
            return server_set_port(server, *(unsigned short*) s_o_arg);
        case S_O_ASCII_ART_LOCATION:
            return server_set_ascii_art(server, s_o_arg);
        case S_O_STATIC_RESOURCE_LOCATION:
            return server_set_static_resource(server, s_o_arg);
        default:
            return -1;
    }
}

int epoll_on_socket(int sock_fd) {
    int epoll_fd = epoll_create1(0);
    pthread_cleanup_push(thread_close_fd, &epoll_fd);

#define MAX_EVENTS 10
    struct epoll_event event, events[MAX_EVENTS];
    event.events = EPOLLIN;
    event.data.fd = sock_fd;

    // Register interested fd.
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sock_fd, &event) < 0) {
        perror("epoll_ctl");
        pthread_exit(NULL);
    }

    syslog(LOG_INFO, "Entering main loop");

    for (;;) {
        // Cancellation point. // Wait for ready list.
        const int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        if (nfds < 0) {
            syslog(LOG_ERR, "epoll_wait() failed %s", strerror(errno));

        }

        for (int i = 0; i < nfds; i++) {
            if (events[i].data.fd == sock_fd) { // Connection incoming.
                int client_fd = accept(sock_fd, NULL, NULL);
                if (client_fd < 0) {
                    syslog(LOG_ERR, "accept() failed %s", strerror(errno));
                    pthread_exit(NULL);
                }
                event.events = EPOLLIN | EPOLLOUT;
                event.data.fd = client_fd;
                if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &event) < 0) {
                    syslog(LOG_ERR, "epoll_ctl() failed %s", strerror(errno));
                }
            } else { // Existing connection sending.
                send(events[i].data.fd, "Hello, world!\n", 14, 0);
                shutdown(events[i].data.fd, SHUT_WR);
                epoll_ctl(epoll_fd, EPOLL_CTL_DEL, events[i].data.fd, NULL);
                close(events[i].data.fd);
            }
        }
    }

    pthread_cleanup_pop(1);
}

void* server_thread_func(void* server_ptr) {
    const server_t* server = server_ptr;
    if (server->ascii_art_path != NULL) {
        print_file(server->ascii_art_path->buffer);
    }
    int sock_fd = wsocket_create_listen(8080);
    pthread_cleanup_push(thread_close_fd, &sock_fd);
    if (sock_fd < 0) {
        syslog(LOG_ERR, "socket failed: %s", strerror(errno));
        pthread_exit(NULL);
    }

    epoll_on_socket(sock_fd);

    pthread_cleanup_pop(1);

    printf("server start on port %i\n", server->port);
    return NULL;
}

int server_start(server_t* server) {
    threadpool = threadpool_create(4);
    syslog(LOG_INFO, "Server starting up...");
    pthread_create(&server_thread, NULL, server_thread_func, server);

    signal(SIGTERM, sig_handler);
    signal(SIGINT, sig_handler);
    signal(SIGQUIT, sig_handler);
    signal(SIGABRT, sig_handler);

    while (!atomic_load(&exit_flag)) {
        sleep(1);
    }

    syslog(LOG_INFO, "Server shutdown complete");
    pthread_cancel(server_thread);
    pthread_join(server_thread, NULL);

    threadpool_destroy(threadpool);
    return 0;
}