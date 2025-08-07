//
// Created by mawe on 8/7/25.
//

#include "whttp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int parse_http_request_line(const cstring_t* request, request_t* request_info) {
    const cstring_t* copy = cstring_copy(request);
    if (request_info == NULL) {
        return -1;
    }
    char* buffer = copy->buffer;
    char* save;
    const char* p = strtok_r(buffer, " ", &save);
    request_info->method = cstring_copy(cstring_create(p)); // TODO: Validate

    p = strtok_r(NULL, " ", &save);
    request_info->uri = cstring_copy(cstring_create(p)); // TODO: Validate

    p = strtok_r(NULL, "\r\n", &save);
    request_info->protocol = cstring_copy(cstring_create(p)); // TODO: Validate

    return 0;
}

void parse_http_headers(const cstring_t* request, request_t* request_info) {
    const cstring_t* copy = cstring_copy(request);
    char* buffer = copy->buffer;

    const long header_start = strstr(buffer, "\r\n") - buffer;
    const long header_end = strstr(buffer, "\r\n\r\n") - buffer;

    char* slice = malloc(header_end - header_start + 1);
    memcpy(slice, buffer + header_start, header_end - header_start);
    slice[header_end - header_start] = '\0';

    cstring_t* header = cstring_create(slice);
    request_info->headers = header;
}

void http_request_destroy(request_t* request_info) {
    if (request_info == NULL) {
        return;
    }
    cstring_destroy(request_info->method);
    cstring_destroy(request_info->uri);
    cstring_destroy(request_info->protocol);
    cstring_destroy(request_info->headers);
    free(request_info);
}

int parse_http_request(const cstring_t* request) {
    request_t* request_info = malloc(sizeof(request_t));
    parse_http_request_line(request, request_info);

    printf("Method: %s\n", request_info->method->buffer);
    printf("URI: %s\n", request_info->uri->buffer);
    printf("Protocol: %s", request_info->protocol->buffer);

    parse_http_headers(request, request_info);
    for (int i = 0; i < request_info->headers->size; i++) {
        printf("%c", request_info->headers->buffer[i] == '\r' ? ' ' : request_info->headers->buffer[i]);
    }
    printf("\n");

    http_request_destroy(request_info);
    return 0;
}
