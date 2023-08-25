# simplified-shell
A custom terminal emulator that capable of handling up to 20 shell commands in a single line without using the "system()" function. Utilizes "fork()", "execl()", "wait()", and "exit()" system functions, handling pipes, redirections, error messages, and signals. Logs child process information to timestamped files upon completion.
