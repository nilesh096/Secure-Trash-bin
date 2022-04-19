#!/bin/sh
#Test functionality of not allowing chown, chmod and touch operations for ubuntu user on /mn/stbfs1/.stb

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


echo "Test for not allowing ubuntu changing the permissions for .stb dir"
su - ubuntu -c 'chmod 0755 /mnt/stbfs1/.stb'
retval=$?

if test $retval != 0 ; then
	echo "Ubuntu user not able to change permissions of .stb dir"
else
	echo "Ubuntu user able to do chmod"
fi


echo "Test for not allowing ubuntu changing the owner of .stb dir"
su - ubuntu -c 'chown ubuntu:ubuntu /mnt/stbfs1/.stb'
retval=$?

if test $retval != 0 ; then
    echo "Ubuntu user not able to change owner of .stb dir"
else
    echo "Ubuntu user able to do chown"
fi

echo "Test for not allowing ubuntu creating new file in .stb dir"
su - ubuntu -c 'chown ubuntu:ubuntu /mnt/stbfs1/.stb'
retval=$?

if test $retval != 0 ; then
    echo "Ubuntu user not able to create a file in .stb dir"
else
    echo "Ubuntu user able to create a file in .stb"
fi


