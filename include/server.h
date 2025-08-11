//
// Created by mawe on 8/11/25.
//

#ifndef SERVER_H
#define SERVER_H
#include <stdbool.h>

typedef struct {
    unsigned short port;
    int thread_count;
    int queue_size;
    int shutdown;
    bool tls;
} server_config_t;

void* server_start(void* config);

#endif //SERVER_H
