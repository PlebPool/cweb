//
// Created by mawe on 8/7/25.
//

#ifndef WHTTP_H
#define WHTTP_H
#include <stddef.h>

#include "cstring.h"

typedef struct {
    cstring_t* method;
    cstring_t* uri;
    cstring_t* protocol;
    cstring_t* headers; // TODO: Make into hashmap
    cstring_t* body;
} request_t;

int parse_http_request(const cstring_t* request);
void http_request_destroy(request_t* request);

#endif //WHTTP_H
