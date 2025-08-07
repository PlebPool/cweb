//
// Created by mawe on 8/7/25.
//

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <wfile.h>
#include <linux/limits.h>
#include <sys/syslog.h>

#include "cstring.h"


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

size_t file_into_buffer(const char* filename, char* buffer, size_t buffer_size) {
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s", filename);
    FILE *fp = fopen(path, "r");
    if (fp == NULL) {
        syslog(LOG_ERR, "cannot open file %s: %s", path, strerror(errno));
        return -1;
    }

    fseek(fp, 0, SEEK_END);
    const size_t file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (file_size > buffer_size) {
        syslog(LOG_ERR, "file %s is too large to fit in buffer", path);
        return -1;
    }

    fread(buffer, file_size, 1, fp);

    fclose(fp);

    return file_size;

}