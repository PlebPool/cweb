//
// Created by mawe on 8/7/25.
//

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <wfile.h>
#include <linux/limits.h>
#include <sys/syslog.h>


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
