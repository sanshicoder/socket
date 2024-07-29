CC = gcc
CFLAGS = -Wall -g
BUILD_DIR = ../bin
TARGET = $(BUILD_DIR)/client
SRCS = $(wildcard *.c)
OBJS = $(SRCS:.c=.o)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -c $^ -o $@

clean:
	rm -f $(TARGET) $(OBJS)