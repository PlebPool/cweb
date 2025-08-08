//
// Created by mawe on 7/23/25.
//
#include "server.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cstring.h"
#include <unistd.h>
#include <syslog.h>

#include "wsocket.h"
#include <sys/epoll.h>
#include <sys/socket.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>

#include <sys/types.h>
#include <sys/syscall.h>

#include "wthread.h"
#include <whttp.h>
#include <wfile.h>

threadpool_t *threadpool;
server_t* server;

pthread_t server_thread;
int exit_flag = 0;

void thread_close_fd(void* fd) {
    close(*(int*) fd);
}

void sig_handler(const int signo) {
    syslog(LOG_INFO, "Received signal %d", signo);
    exit_flag = 1;
}

int server_init(server_t* server) {
    return 0;
}

void server_destroy(const server_t* server) {
    cstring_destroy(server->ascii_art_path);
    server = NULL;
}

int server_set_port(server_t* server, const unsigned short port) {
    server->port = port;
    return 0;
}

int server_set_ascii_art(server_t* server, const cstring_t* ascii_art_path) {
    cstring_t* string = malloc(sizeof(cstring_t)); // TODO: Put this in cstring_copy
    string->buffer = malloc(ascii_art_path->size);
    memcpy(string->buffer, ascii_art_path->buffer, ascii_art_path->size);
    server->ascii_art_path = string;
    return 0;
}

int server_set_static_resource(server_t* server, const cstring_t* static_resource_path) {
    return 0; // TODO: Does nothing.
}

int server_set_index_page_file(server_t* server, const cstring_t* index_page_file_path) {
    cstring_t* string = malloc(sizeof(cstring_t)); // TODO: Put this in cstring_copy
    string->buffer = malloc(index_page_file_path->size);
    memcpy(string->buffer, index_page_file_path->buffer, index_page_file_path->size);
    server->index_html_path = string;
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
        case S_O_INDEX_PAGE_FILE_LOCATION:
            return server_set_index_page_file(server, s_o_arg);
        default:
            return -1;
    }
}

void handle_request(void* fd_in) {
    const int fd = *(int*) fd_in;
    char* buffer = malloc(sizeof(char) * 8096 +1);
    memset(buffer, 0, 8096 + 1);
    const ssize_t n = recv(fd, buffer, 8096, 0);
    if (n < 0) {
        syslog(LOG_ERR, "recv() failed %s", strerror(errno));
        shutdown(fd, SHUT_WR); // TODO Move into cleanup function
        close(fd);
        free(buffer);
        return;
    }
    if (n == 0) { // Client has closed connection.
        syslog(LOG_ERR, "Connection closed by client");
        shutdown(fd, SHUT_WR); // TODO Move into cleanup function
        close(fd);
        free(buffer);
        return;
    }

    buffer[n] = '\0';
    cstring_t* request = cstring_create(buffer);
    parse_http_request(request);
    cstring_destroy(request);

    const long pid = syscall(SYS_gettid);
    syslog(LOG_INFO, "Request from fd %i is being handled by thread %li", fd, pid);

    memset(buffer, 0, 8096 + 1); // Reusing buffer for response

    const size_t size = file_into_buffer(server->index_html_path->buffer, buffer, 8096);

    // Logic to handle the request.
    const char* str = "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/html\r\n\r\n";
    send(fd, str, strlen(str), 0);
    send(fd, buffer, size, 0);

    // Closing connection.
    shutdown(fd, SHUT_WR);
    close(fd);
    free(buffer);
}

int epoll_on_socket(const int sock_fd) {
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
                const int client_fd = accept(sock_fd, NULL, NULL);
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
                threadpool_add_task(threadpool, handle_request, &events[i].data.fd);
                epoll_ctl(epoll_fd, EPOLL_CTL_DEL, events[i].data.fd, NULL);
                // TODO: We currently consider it handled when it's turned over to a thread. (Might be bad)
            }
        }
    }

    pthread_cleanup_pop(1);
}

// ReSharper disable once CppParameterMayBeConstPtrOrRef
void* server_thread_func(void* server_ptr) {
    server = server_ptr;
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
    return NULL;
}

int server_start(server_t* server) {
    threadpool = threadpool_create(4);
    syslog(LOG_INFO, "Server starting up on port %i", server->port);
    pthread_create(&server_thread, NULL, server_thread_func, server);

    signal(SIGTERM, sig_handler);
    signal(SIGINT, sig_handler);
    signal(SIGQUIT, sig_handler);
    signal(SIGABRT, sig_handler);

    while (!atomic_load(&exit_flag)) {
        sleep(1);
    }

    pthread_cancel(server_thread);
    pthread_join(server_thread, NULL);
    syslog(LOG_INFO, "Server shutdown complete");

    threadpool_destroy(threadpool);
    return 0;
}