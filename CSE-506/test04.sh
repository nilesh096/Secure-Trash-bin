#!/bin/sh
#Test functionality of root user being able to view 2 files and ubuntu user being able to view 1 file

cd /usr/src/hw2-nrustagi/fs/stbfs
umount /mnt/stbfs1
rmmod stbfs.ko
rm -rf /test/src1/.stb/*
rm -rf /test/src1/*


cd /usr/src/hw2-nrustagi/CSE-506
#make clean; make stbfsctl
cd /usr/src/hw2-nrustagi/fs/stbfs
#make clean; make stbfs-abc
insmod stbfs.ko
mkdir -p /test/src1/.stb
mkdir -p /mnt/stbfs1/
mkdir -p /test/src1/test_undelete
chmod 0777 /test/src1/.stb
chmod 0777 /test/src1/

echo "Mounting the stbfs"
mount -t stbfs -o enc=MySecretPa55 /test/src1/ /mnt/stbfs1/


echo "HelloWorld" >> /mnt/stbfs1/test1.txt
retval=`rm /mnt/stbfs1/test1.txt`
if [ $retval=0 ]; then 
  echo "File deleted successfully"
else
  echo "File deletion failed"
  exit 1
fi


su - ubuntu -c 'echo "HelloWorld" >> /mnt/stbfs1/test2.txt'
retval=`su - ubuntu -c 'rm /mnt/stbfs1/test2.txt'`
if [ $retval=0 ]; then 
  echo "File deleted successfully"
else
  echo "File deletion failed"
  exit 1
fi

val=`su - ubuntu -c 'ls /mnt/stbfs1/.stb | wc -l'`
if [ $val=1 ]; then echo "Ubuntu can view 1 file"; fi

echo "Contents of .stb dir for ubuntu user is"
for i in `su - ubuntu -c 'ls /mnt/stbfs1/.stb'`; do echo $i; done;


val=`ls /mnt/stbfs1/.stb | wc -l`
if [ $val=1 ]; then echo "Root can view 2 files"; fi

echo "Contents of .stb dir for root user is"
for i in `ls /mnt/stbfs1/.stb`; do echo $i; done;