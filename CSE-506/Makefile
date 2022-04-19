INC=/lib/modules/$(shell uname -r)/build/arch/x86/include

all: stbfsctl

stbfsctl: stbfs_user.c
	gcc -Wall -Werror -I$(INC)/generated/uapi -I$(INC)/uapi stbfs_user.c -o stbfsctl

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f stbfsctl
