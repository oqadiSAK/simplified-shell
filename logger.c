#include "logger.h"

void log_command(char *command, int childId)
{
    char *time_str = current_time_string();
    char *buffer = (char *)malloc(1000 * sizeof(char));
    int fd;

    if (!buffer)
    {
        perror("Error while allocating buffer");
        exit(EXIT_FAILURE);
    }
    tidy_time_str(time_str);
    fd = open_file(time_str, buffer);
    write_to_file(fd, time_str, buffer, childId, command);
    free(buffer);
    close_file(fd);
}

char *current_time_string()
{
    struct timespec ts;
    struct tm *timeinfo;
    static char buffer[TIME_STR_MAX_LEN + 1];

    clock_gettime(CLOCK_REALTIME, &ts);
    timeinfo = localtime(&ts.tv_sec);
    strftime(buffer, TIME_STR_MAX_LEN, "log_%Y_%m_%d_%H.%M.%S", timeinfo);
    snprintf(buffer + strlen(buffer), TIME_STR_MAX_LEN - strlen(buffer),
             ".%09ld", ts.tv_nsec);

    return buffer;
}

void tidy_time_str(char *time_str)
{
    size_t len = strlen(time_str);
    if (len > 0 && time_str[len - 1] == '\n')
    {
        time_str[len - 1] = '\0';
    }
}

int open_file(char *time_str, char *buffer)
{
    char *path = (char *)malloc(MAX_PATHNAME_LEN * sizeof(char));
    int fd;
    set_path(path, time_str, buffer);
    check_path_exist();
    fd = open(path, O_WRONLY | O_CREAT, FILE_MODE);
    if (fd == -1)
    {
        perror("Error while opening log file");
        free(buffer);
        exit(EXIT_FAILURE);
    }
    free(path);
    return fd;
}

void set_path(char *path, char *time_str, char *buffer)
{
    if (!path)
    {
        perror("Error while allocating path");
        free(buffer);
        exit(EXIT_FAILURE);
    }

    sprintf(path, "logs/%s", time_str);
}

void check_path_exist()
{
    struct stat st;
    if (stat("./logs", &st) == -1)
    {
        mkdir("./logs", FILE_MODE);
    }
}

void write_to_file(int log_fd, char *time_str, char *buffer, int childId, char *command)
{

    int bytes_written = sprintf(buffer, "PID: %d\nCommand: %s\n", childId, command);
    if (bytes_written < 0)
    {
        perror("Error while formatting log message");
        free(buffer);
        close(log_fd);
        exit(EXIT_FAILURE);
    }

    if (write(log_fd, buffer, bytes_written) == -1)
    {
        perror("Error while writing to log file");
        free(buffer);
        close(log_fd);
        exit(EXIT_FAILURE);
    }
}

void close_file(int fd)
{
    if (close(fd) == -1)
    {
        perror("Error while closing log file");
        exit(EXIT_FAILURE);
    }
}
