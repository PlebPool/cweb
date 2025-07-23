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

server_t server_create() {
    const server_t server = {0};
    return server;
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

int server_set_opt(server_t* server, int s_o_opt, void* s_o_arg) {
    switch (s_o_opt) {
        case S_O_PORT:
            return server_set_port(server, *(unsigned short*) s_o_arg);
        case S_O_ASCII_ART:
            return server_set_ascii_art(server, s_o_arg);
        default:
            return -1;
    }
}

int server_start(server_t* server) {
    printf("server start\n");
    return 0;
}