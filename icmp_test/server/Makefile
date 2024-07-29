# variable definitions 
CC = gcc
CFLAGS = -Wall -g
BUILD_DIR = ../bin
TARGET = $(BUILD_DIR)/server
SRCS = icmp_server.c
#SRCS = $(wildcard *.c)
OBJS = $(SRCS:.c=.o)

# phony objects
.PHONY: all clean

all: $(TARGET)

# output target file
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS)

# 模式匹配规则:当make需要目标 xyz.o 时，自动生成一条 xyz.o: xyz.c 规则
%.o: %.c
	$(CC) $(CFLAGS) -c $^ -o $@

# clean the generated files
clean:
	rm -f $(TARGET) $(OBJS)