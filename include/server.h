//
// Created by mawe on 7/23/25.
//

#ifndef SERVER_H
#define SERVER_H

typedef struct {
    unsigned short port;
} server_t;

server_t server_create();
void server_destroy(server_t* server);

#define S_O_PORT 1
int server_ctl(server_t* server, int s_o_cmd, void* s_o_arg);

int server_start(server_t* server);

#endif //SERVER_H
