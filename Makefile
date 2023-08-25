CC = gcc
CFLAGS = -Wall -pedantic-errors
ccflags-y := -std=gnu11

all: sak-shell

sak-shell: main.c logger.c
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -rf sak-shell logs
