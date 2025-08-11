//
// Created by mawe on 8/11/25.
//

#include "server.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/syslog.h>
#include <sys/epoll.h>
#include <sys/socket.h>

#include "wsocket.h"
#include "cthread.h"

#include <openssl/ssl.h>
#include <openssl/err.h>

SSL_CTX* ctx = NULL;

void thread_close_fd(void *arg) {
    const int *fd = arg;
    close(*fd);
}

void thread_destroy_threadpool(void *arg) {
    threadpool_t *pool = arg;
    threadpool_destroy(pool);
}

SSL_CTX* initialize_openssl() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    return ctx;
}

void https_handler(void *arg) {
    const int fd = *(int *)arg;
    char buffer[8096];

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, fd);

    if (SSL_accept(ssl) < 0) {
        syslog(LOG_ERR, "SSL_accept() failed %s", strerror(errno));
        return;
    }

    syslog(LOG_INFO, "SSL connection accepted");
    const ssize_t n_read = SSL_read(ssl, buffer, sizeof(buffer));

    for (int i = 0; i < n_read; i++) {
        if (buffer[i] != '\r') {
            printf("%c", buffer[i]);
        }
    }

    const char *response = "HTTP/1.1 200 OK\r\n\r\n";
    SSL_write(ssl, response, 16);

    SSL_shutdown(ssl);
    SSL_free(ssl);
    shutdown(fd, SHUT_WR);
    close(fd);
}

void http_handler(void *arg) {
    const int fd = *(int *)arg;
    char buffer[8096];

    const ssize_t n_read = recv(fd, buffer, sizeof(buffer), 0);
    if (n_read < 0) {
        syslog(LOG_ERR, "recv() failed %s", strerror(errno));
        return;
    }

    for (int i = 0; i < n_read; i++) {
        if (buffer[i] != '\r') {
            printf("%c", buffer[i]);
        }
    }

    send(fd, "HTTP/1.1 200 OK\r\n\r\n", 16, 0);
    shutdown(fd, SHUT_WR);
    close(fd);
}

int epoll_on_socket(const int sock_fd, threadpool_t *threadpool, void (*handle_request)(void *)) {
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

    for (;;) {
        // Cancellation point. // Wait for a ready list.
        const int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        if (nfds < 0) {
            syslog(LOG_ERR, "epoll_wait() failed: %s", strerror(errno));
            break;
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
    return 0;
}

void* server_start(void* arg) {
    const server_config_t *config = arg;

    // Create socket // bind, listen...
    const int sock_fd = wsocket_create_listen(config->port);
    pthread_cleanup_push(thread_close_fd, &sock_fd);
    if (sock_fd < 0) {
        syslog(LOG_ERR, "Failed to create socket: %s", strerror(errno));
        return NULL;
    }

    void (*handler)(void *arg) = NULL;
    if (config->tls) {
        // SSL init
        if (ctx == NULL) {
            SSL_CTX* ctx_tmp = initialize_openssl();
            if (ctx_tmp == NULL) {
                syslog(LOG_ERR, "Failed to initialize OpenSSL");
                return NULL;
            }
            ctx = ctx_tmp;
            if (SSL_CTX_use_certificate_file(ctx, "./resources/cert.pem", SSL_FILETYPE_PEM) <= 0 ||
                SSL_CTX_use_PrivateKey_file(ctx, "./resources/key.pem", SSL_FILETYPE_PEM) <= 0) {
                        ERR_print_errors_fp(stderr);
                        exit(EXIT_FAILURE);
            }
        }
        handler = https_handler;
        syslog(LOG_INFO, "HTTPS server created on port %i", config->port);
    } else {
        handler = http_handler;
        syslog(LOG_INFO, "HTTP server created on port %i", config->port);
    }

    threadpool_t *pool = threadpool_create(config->thread_count);
    pthread_cleanup_push(thread_destroy_threadpool, pool);

    epoll_on_socket(sock_fd, pool, handler); // Main loop.

    if (config->tls) {
        // SSL cleanup
        SSL_CTX_free(ctx);
        EVP_cleanup();
    }

    pthread_cleanup_pop(1);
    pthread_cleanup_pop(1);
    return NULL;
}
