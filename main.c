#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <stdbool.h>
#include <signal.h>
#include <errno.h>
#include "logger.h"
#define GRN "\x1B[32m"
#define BLU "\x1B[34m"
#define RESET "\x1B[0m"
#define FILE_MODE 0777
#define INPUT_MAX_LENGTH 2048
#define MAX_TOKEN_NUM 128
#define MAX_CHILD_NUM 20

void check_usage(int argc);
void set_signal_handlers();
void add_mask();
void remove_mask();
void prompt();
void prompt_help();
void get_input(char *input_buffer, int buffer_size);
int parse_buffer(char **param, char *buf, const char *c);
void remove_space(char *buf);
void execute_pipeline(char **commands, char **argv, char **sub_argv, int number_of_token);
bool check_process_num(int num);
bool check_open_file(int fd);
bool check_incorrect_redirect(int number_of_token);
void create_pipe(int fd[MAX_CHILD_NUM][2], int limit, int i);
void handle_child_pipeline(int fd[MAX_CHILD_NUM][2], int limit, int i);
void handle_parent_pipeline(int fd[MAX_CHILD_NUM][2], int i);
void execute_redirect(char **commands, char **argv, int number_of_token, char c);
void execute_single_redirect(char **commands, char **argv, char *command_str, int number_of_token, char c);
void execute_single(char **argv, char *command_str, int number_of_token);
void run_cd(char **argv, int number_of_argv);
void clean_up(char *input_buffer, char **tokens, char **argv, char **sub_argv, char *single_command, int *number_of_token);
void clean_tokens(char **tokens);

volatile sig_atomic_t signal_received = 0;
struct sigaction sa_clean;
sigset_t block_mask, orig_mask;

void cleaner_signal_handler(int s)
{
    char *signal_name;
    if (s == SIGINT)
        signal_name = "SIGINT";
    else if (s == SIGTSTP)
        signal_name = "SIGTSTP";
    else if (s == SIGQUIT)
        signal_name = "SIGQUIT";
    else
        signal_name = "UNKNOWN SIGNAL";

    write(STDOUT_FILENO, "\n", 1);                          /* write is a sync-signal-safe function */
    write(STDOUT_FILENO, signal_name, strlen(signal_name)); /* strlen is async-signal-safe function */
    write(STDOUT_FILENO, " signal is received\n", 20);
    signal_received = 1;
}

int main(int argc, char *main_argv[])
{
    char input_buffer[INPUT_MAX_LENGTH], single_command[INPUT_MAX_LENGTH], *tokens[MAX_TOKEN_NUM], *argv[MAX_TOKEN_NUM], *sub_argv[MAX_TOKEN_NUM];
    int number_of_token, i = -1;
    check_usage(argc);
    set_signal_handlers();
    memset(input_buffer, 0, INPUT_MAX_LENGTH);
    memset(single_command, 0, INPUT_MAX_LENGTH);
    memset(tokens, 0, (sizeof(char *)) * MAX_TOKEN_NUM);
    memset(argv, 0, (sizeof(char *)) * MAX_TOKEN_NUM);
    memset(sub_argv, 0, (sizeof(char *)) * MAX_TOKEN_NUM);
    printf("sak shell is started\n");
    while (1)
    {
        add_mask();
        i++;
        if (i > 0)
            clean_up(input_buffer, tokens, argv, sub_argv, single_command, &number_of_token);
        prompt();
        get_input(input_buffer, sizeof(input_buffer));
        if (signal_received)
            continue;
        strcpy(single_command, input_buffer);
        if (strcmp(input_buffer, "\n") == 0)
        {
            continue;
        }
        else if (strchr(input_buffer, '|') != NULL)
        {
            number_of_token = parse_buffer(tokens, input_buffer, "|");
            if (number_of_token == -1)
                continue;
            execute_pipeline(tokens, argv, sub_argv, number_of_token);
        }
        else if (strchr(input_buffer, '>') != NULL)
        {
            number_of_token = parse_buffer(tokens, input_buffer, ">");
            if (number_of_token == -1)
                continue;

            if (check_incorrect_redirect(number_of_token))
                execute_single_redirect(tokens, argv, single_command, number_of_token, '>');
        }
        else if (strchr(input_buffer, '<') != NULL)
        {
            number_of_token = parse_buffer(tokens, input_buffer, "<");
            if (number_of_token == -1)
                continue;
            if (check_incorrect_redirect(number_of_token))
                execute_single_redirect(tokens, argv, single_command, number_of_token, '<');
        }
        else
        {
            number_of_token = parse_buffer(tokens, input_buffer, " ");
            if (number_of_token == -1)
                continue;
            if (strcmp(tokens[0], ":q") == 0)
            {
                break;
            }
            else if (strcmp(tokens[0], "cd") == 0)
            {
                run_cd(tokens, number_of_token);
            }
            else if (strcmp(tokens[0], "help") == 0)
            {
                prompt_help();
            }
            else
            {
                execute_single(tokens, single_command, number_of_token);
            }
        }
    }
    clean_up(input_buffer, tokens, argv, sub_argv, single_command, &number_of_token);
    printf("\nBYE\n");
    return 0;
}

void check_usage(int argc)
{
    if (argc != 1)
    {
        printf("Program is used incorrectly.\nThe usage is ./sak-shell\nThis program does not take any argument\n");
        exit(1);
    }
}

void set_signal_handlers()
{
    sa_clean.sa_handler = cleaner_signal_handler;
    sigaction(SIGINT, &sa_clean, NULL);
    sigaction(SIGTSTP, &sa_clean, NULL);
    sigaction(SIGQUIT, &sa_clean, NULL);
}

void add_mask()
{
    sigemptyset(&block_mask);
    sigaddset(&block_mask, SIGCHLD);
    sigprocmask(SIG_BLOCK, &block_mask, &orig_mask);
}

void add_additional_mask()
{
    sigaddset(&block_mask, SIGINT);
    sigaddset(&block_mask, SIGQUIT);
    sigprocmask(SIG_BLOCK, &block_mask, &orig_mask);
}

void remove_mask()
{
    sigprocmask(SIG_SETMASK, &orig_mask, NULL);
}

void prompt()
{
    char current_path[PATH_MAX];
    if (getcwd(current_path, sizeof(current_path)) == NULL)
    {
        perror("Error happened when getting current path(getcwd)");
        exit(EXIT_FAILURE);
    }
    printf(GRN "\nsak-sh:" RESET);
    printf(BLU "%s" RESET, current_path);
    printf("$ ");
}

void prompt_help()
{
    printf("\nSAK shell, version 1.0, release 1.0\n");
    printf("Supported internal commands are: 'cd', ':q', 'help'\n");
    printf("Pipes are supported but at most there can be 19 pipe(20 processes)\n");
    printf("Ex. 'ls -la | grep file'\n");
    printf("Redirections are supported\n");
    printf("Ex. 'ls > file'\n");
    printf("Redirections and pipes can be mixed\n");
    printf("Ex. 'ls -la | grep file > results.txt'\n");
}

void get_input(char *input_buffer, int buffer_size)
{
    if (fgets(input_buffer, buffer_size, stdin) == NULL && ferror(stdin) != 0)
    {
        perror("fgets() failed");
        if (errno != EINTR)
            exit(EXIT_FAILURE);
    }
}

int parse_buffer(char **tokens, char *buf, const char *c)
{
    char *token = NULL;
    int counter = 0;
    token = strtok(buf, c);
    while (token)
    {
        if (signal_received)
            return -1;
        tokens[counter] = malloc(strlen(token) + 1);
        if (tokens[counter] == NULL)
        {
            fprintf(stderr, "Failed to allocate memory\n");
            return -1;
        }
        strcpy(tokens[counter], token);
        remove_space(tokens[counter]);
        token = strtok(NULL, c);
        counter++;
    }
    tokens[counter] = NULL;
    return counter;
}

void remove_space(char *buf)
{
    if (buf[strlen(buf) - 1] == ' ' || buf[strlen(buf) - 1] == '\n')
        buf[strlen(buf) - 1] = '\0';
    if (buf[0] == ' ' || buf[0] == '\n')
        memmove(buf, buf + 1, strlen(buf));
}

void execute_pipeline(char **commands, char **argv, char **sub_argv, int number_of_token)
{
    int i, fd[MAX_CHILD_NUM][2], number_of_sub_token, childId;
    if (!check_process_num(number_of_token))
        return;
    for (i = 0; i < number_of_token; i++)
    {
        create_pipe(fd, number_of_token, i);
        if ((childId = fork()) == 0)
        {
            remove_mask();
            handle_child_pipeline(fd, number_of_token, i);
            if (strchr(commands[i], '<') != NULL)
            {
                number_of_sub_token = parse_buffer(argv, commands[i], "<");
                if (!check_incorrect_redirect(number_of_sub_token))
                    exit(EXIT_FAILURE);
                execute_redirect(argv, sub_argv, number_of_sub_token, '<');
            }
            else if (strchr(commands[i], '>') != NULL)
            {
                number_of_sub_token = parse_buffer(argv, commands[i], ">");
                if (!check_incorrect_redirect(number_of_sub_token))
                    exit(EXIT_FAILURE);
                execute_redirect(argv, sub_argv, number_of_sub_token, '>');
            }
            else
            {
                parse_buffer(argv, commands[i], " ");
                execvp(argv[0], argv);
                perror("Incorrect input");
                exit(EXIT_FAILURE);
            }
        }
        else if (childId == -1)
        {
            perror("fork failed");
            exit(EXIT_FAILURE);
        }
        else
        {
            add_additional_mask();
            handle_parent_pipeline(fd, i);
            wait(NULL);
            log_command(commands[i], childId);
        }
        remove_mask();
    }
}

bool check_process_num(int num)
{
    if (num > MAX_CHILD_NUM)
    {
        fprintf(stderr, "The program does not support that many processes in a pipe!");
        return false;
    }
    return true;
}

bool check_open_file(int fd)
{
    if (fd == -1)
    {
        perror("cannot open file");
        return false;
    }
    return true;
}

bool check_incorrect_redirect(int number_of_token)
{
    if (number_of_token != 2)
    {
        fprintf(stderr, "Incorrect input redirection!(has to to be in this form: command < file or command > file)\n");
        return false;
    }
    return true;
}

void create_pipe(int fd[MAX_CHILD_NUM][2], int limit, int i)
{
    if (i != limit - 1)
    {
        if (i < 0 || i >= MAX_CHILD_NUM)
        {
            fprintf(stderr, "invalid index for fd array\n");
            exit(EXIT_FAILURE);
        }
        if (pipe(fd[i]) == -1)
        {
            perror("pipe creating was not successfull");
            exit(EXIT_FAILURE);
        }
    }
}

void handle_child_pipeline(int fd[MAX_CHILD_NUM][2], int limit, int i)
{
    if (i != limit - 1)
    {
        dup2(fd[i][1], 1);
        close(fd[i][0]);
        close(fd[i][1]);
    }

    if (i != 0)
    {
        dup2(fd[i - 1][0], 0);
        close(fd[i - 1][1]);
        close(fd[i - 1][0]);
    }
}

void handle_parent_pipeline(int fd[MAX_CHILD_NUM][2], int i)
{
    if (i != 0)
    {
        close(fd[i - 1][0]);
        close(fd[i - 1][1]);
    }
}

void execute_redirect(char **commands, char **argv, int number_of_token, char c)
{
    int fd;
    remove_space(commands[1]);
    parse_buffer(argv, commands[0], " ");

    if (c == '<')
    {
        fd = open(commands[1], O_RDONLY | O_CREAT, FILE_MODE);
        if (!check_open_file(fd))
        {
            perror("error happened while opening file");
            exit(EXIT_FAILURE);
        }
        dup2(fd, 0);
        close(fd);
    }
    else if (c == '>')
    {
        fd = open(commands[1], O_WRONLY | O_CREAT, FILE_MODE);
        if (!check_open_file(fd))
        {
            perror("error happened while opening file");
            exit(EXIT_FAILURE);
        }
        dup2(fd, 1);
        close(fd);
    }
    execvp(argv[0], argv);
    perror("Incorrect input");
    exit(EXIT_FAILURE);
}

void execute_single_redirect(char **commands, char **argv, char *command_str, int number_of_token, char c)
{
    int fd, childId;
    remove_space(commands[1]);
    parse_buffer(argv, commands[0], " ");

    if ((childId = fork()) == 0)
    {
        remove_mask();
        if (c == '<')
        {
            fd = open(commands[1], O_RDONLY, FILE_MODE);
            if (!check_open_file(fd))
            {
                perror("error happened while opening file");
                exit(EXIT_FAILURE);
            }
            dup2(fd, 0);
            close(fd);
        }
        else if (c == '>')
        {
            fd = open(commands[1], O_WRONLY, FILE_MODE);
            if (!check_open_file(fd))
            {
                perror("error happened while opening file");
                exit(EXIT_FAILURE);
            }
            dup2(fd, 1);
            close(fd);
        }
        else
        {
            exit(EXIT_FAILURE);
        }
        execvp(argv[0], argv);
        perror("Incorrect input");
        exit(EXIT_FAILURE);
    }
    else if (childId == -1)
    {
        perror("fork failed");
        exit(EXIT_FAILURE);
    }
    else
    {
        add_additional_mask();
        wait(NULL);
        log_command(command_str, childId);
    }
    remove_mask();
}

void execute_single(char **argv, char *command_str, int number_of_token)
{
    int childId;
    if ((childId = fork()) == 0)
    {
        remove_mask();
        execvp(argv[0], argv);
        perror("Incorrect input");
        exit(EXIT_FAILURE);
    }
    else if (childId == -1)
    {
        perror("fork failed");
        exit(EXIT_FAILURE);
    }
    else
    {
        add_additional_mask();
        wait(NULL);
        log_command(command_str, childId);
    }
    remove_mask();
}

void run_cd(char **argv, int number_of_argv)
{
    /* if there is no path, route to home */
    if (number_of_argv > 2)
    {
        fprintf(stderr, "\ncd: too many arguments\n");
        return;
    }
    else if (argv[1] == NULL)
    {
        chdir("/");
    }
    else
    {
        if (chdir(argv[1]) == -1)
        {
            fprintf(stderr, " %s: no such directory\n", argv[1]);
            return;
        }
    }
}

void clean_up(char *input_buffer, char **tokens, char **argv, char **sub_argv, char *single_command, int *number_of_token)
{
    signal_received = 0;
    memset(input_buffer, 0, INPUT_MAX_LENGTH);   /* clear input buffer */
    memset(single_command, 0, INPUT_MAX_LENGTH); /* clear single_command */
    *number_of_token = 0;                        /*  reset number of tokens */
    clean_tokens(tokens);
    clean_tokens(argv);
    clean_tokens(sub_argv);
}

void clean_tokens(char **tokens)
{
    int i;
    for (i = 0; i < MAX_TOKEN_NUM; i++)
    {
        if (tokens[i] != NULL)
        {
            free(tokens[i]);
            tokens[i] = NULL;
        }
    }
}
