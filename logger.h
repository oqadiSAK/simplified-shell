#ifndef LOGGER_H
#define LOGGER_H
#include <time.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#define FILE_MODE 0777
#define TIME_STR_MAX_LEN 32
#define MAX_PATHNAME_LEN 50

void log_command(char *command, int childId);
char *current_time_string();
void tidy_time_str(char *time_str);
int open_file(char *time_str, char *buffer);
void set_path(char *path, char *time_str, char *buffer);
void check_path_exist();
void write_to_file(int log_fd, char *time_str, char *buffer, int childId, char *command);
void close_file(int fd);

#endif