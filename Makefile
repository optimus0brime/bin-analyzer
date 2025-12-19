CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -O2
OBJS = main.o detect.o analyze.o view.o utils.o

binanalyzer: $(OBJS)
	$(CC) $(CFLAGS) -o binanalyzer $(OBJS) -lm

clean:
	rm -f *.o binanalyzer

.PHONY: clean

