//
// Created by mawe on 8/11/25.
//

#include "server.h"

#include <errno.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <bits/signum-generic.h>
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
    int fd = *(int *)arg;
    char buffer[1024];
    ssize_t nread;

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, fd);

    if (SSL_accept(ssl) <= 0) {
        syslog(LOG_ERR, "SSL_accept() failed %s", strerror(errno));
        return;
    }
    syslog(LOG_INFO, "SSL connection accepted");
    nread = SSL_read(ssl, buffer, sizeof(buffer));

    for (int i = 0; i < nread; i++) {
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
    int fd = *(int *)arg;
    char buffer[1024];
    ssize_t nread;

    nread = recv(fd, buffer, sizeof(buffer), 0);
    if (nread < 0) {
        syslog(LOG_ERR, "recv() failed %s", strerror(errno));
        return;
    }

    for (int i = 0; i < nread; i++) {
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

    syslog(LOG_INFO, "Entering main loop");

    for (;;) {
        // Cancellation point. // Wait for ready list.
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
}

void* server_start(void* arg) {
    const server_config_t *config = arg;

    // Create socket // bind, listen...
    const int sock_fd = wsocket_create_listen(config->port);
    if (sock_fd < 0) {
        syslog(LOG_ERR, "Failed to create socket: %s", strerror(errno));
        return NULL;
    }

    syslog(LOG_INFO, "Socket created on port %i", config->port);

    void (*handler)(void *arg) = NULL;
    if (config->tls) {
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
    } else {
        handler = http_handler;
    }

    threadpool_t *pool = threadpool_create(config->thread_count);

    epoll_on_socket(sock_fd, pool, handler);

    if (config->tls) {
        // Perform SSL cleanup
        SSL_CTX_free(ctx);
        EVP_cleanup();
    }

    threadpool_destroy(pool);
    return NULL;
}
