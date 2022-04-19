#!/bin/sh
#Test functionality of undelete a file

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



cd /mnt/stbfs1/test_undelete
ls /mnt/stbfs1/.stb | xargs -I {} /usr/src/hw2-nrustagi/CSE-506/stbfsctl -u {}

if cmp test1.txt compare_test.txt ; then
	echo "input and output files contents are the same"
	exit 0
else
	echo "test_cryptocopy: input and output files contents DIFFER"
	exit 1
fi

