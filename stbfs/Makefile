STBFS_VERSION="0.1"

EXTRA_CFLAGS += -DSTBFS_VERSION=\"$(STBFS_VERSION)\"

obj-m += stbfs.o

stbfs-y := dentry.o file.o inode.o main.o super.o lookup.o mmap.o

stbfs-abc:
	make -Wall -Werror -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
