#!/bin/sh
#Test functionality of root user's file stored in .stb directory after deleting the file
#After deleting the file, the file count of /mnt/stbfs/.stb should be 1

if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

cd /usr/src/hw2-nrustagi/CSE-506
make clean; make stbfsctl
cd /usr/src/hw2-nrustagi/fs/stbfs
make clean; make stbfs-abc
insmod stbfs.ko
mkdir -p /test/src1/.stb
mkdir -p /mnt/stbfs1/
mkdir -p /test/src1/test_undelete
chmod 0777 /test/src1/.stb
chmod 0777 /test/src1/

echo "Mounting the stbfs"
mount -t stbfs -o enc=MySecretPa55 /test/src1/ /mnt/stbfs1/

echo "HelloWorld" >> /mnt/stbfs1/test1.txt
echo "HelloWorld" >> /mnt/stbfs1/test_undelete/compare_test.txt
retval=`rm /mnt/stbfs1/test1.txt`
if [ $retval=0 ]; then 
  echo "File deleted successfully"
else
  echo "File deletion failed"
  exit 1
fi


val=`ls /mnt/stbfs1/ | wc -l`
if [ $val=0 ]; then echo "File successfully moved from /mnt/stbfs1 to /mnt/stbfs/.stb"; fi
val=`ls /mnt/stbfs1/.stb | wc -l`
echo "Contents of .stb dir are"
for i in `ls /mnt/stbfs1/.stb`; do echo $i; done;
if [ $val=1 ]; then echo "Test case succeeded"; fi




