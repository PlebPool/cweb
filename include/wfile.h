//
// Created by mawe on 8/7/25.
//

#ifndef WFILE_H
#define WFILE_H

void print_file(const char* filename);

size_t file_into_buffer(const char* filename, char* buffer, size_t buffer_size);

#endif //WFILE_H
