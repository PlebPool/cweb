//
// Created by mawe on 7/23/25.
//

#ifndef SERVER_H
#define SERVER_H
#include "../../cstring/include/cstring.h"

typedef struct {
    unsigned short port;
    cstring_t* ascii_art_path;
    cstring_t* index_html_path;
} server_t;

int server_init(server_t* server);
void server_destroy(const server_t* server);

#define S_O_PORT 1 // Port to be used by the server
#define S_O_ASCII_ART_LOCATION 2 // Path to the ascii art file to be printed on startup
#define S_O_STATIC_RESOURCE_LOCATION 3
#define S_O_INDEX_PAGE_FILE_LOCATION 4
int server_set_opt(server_t* server, int s_o_opt, void* s_o_arg);

int server_start(server_t* server);

#endif //SERVER_H
