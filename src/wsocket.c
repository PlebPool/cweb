//
// Created by mawe on 8/11/25.
//

#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <syslog.h>
#include <fcntl.h>
#include <unistd.h>

int get_addr(const unsigned short port, struct sockaddr_in* addr) {
    addr->sin_family = AF_INET;
    addr->sin_port = htons(port);
    addr->sin_addr.s_addr = INADDR_ANY;
    return 0;
}

int wsocket_create_listen(unsigned short port) {
    const int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        syslog(LOG_ERR, "socket failed: %s", strerror(errno));
        return -1;
    }

    if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0) {
        syslog(LOG_ERR, "setsockopt failed: %s", strerror(errno));
        goto cleanup;
    }

    int flags = fcntl(sock_fd, F_GETFL);
    if (flags < 0) {
        syslog(LOG_ERR, "fcntl failed: %s", strerror(errno));
        goto cleanup;
    }
    flags |= O_NONBLOCK;
    fcntl(sock_fd, F_SETFL, flags);

    struct sockaddr_in addr;
    get_addr(port, &addr);

    if (bind(sock_fd, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
        syslog(LOG_ERR, "bind failed: %s", strerror(errno));
        goto cleanup;
    }

    if (listen(sock_fd, 10) < 0) {
        syslog(LOG_ERR, "listen failed: %s", strerror(errno));
        goto cleanup;
    }

    return sock_fd;

    cleanup:
        close(sock_fd);
    return -1;
}