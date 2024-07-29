.PHONY: all clean client server 

all: server client

server:
	$(MAKE) -C server
# $(MAKE) 是一个自动变量，表示调用当前的 Make 程序。它通常是 make 命令本身。
#-C server 选项告诉 make 切换到 server 目录，然后执行该目录中的 Makefile。

client:
	$(MAKE) -C client

clean:
	$(MAKE) -C server clean
	$(MAKE) -C client clean
	rm -rf bin/*