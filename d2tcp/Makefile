obj-m += tcp_d2tcp.o
EXTRA_CFLAGS += -DD2TCP_DEBUG

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
