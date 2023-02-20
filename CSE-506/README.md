# HOMEWORK ASSIGNMENT 2
* Submitted By: Nilesh Rustagi
* SBU ID: 113259870

# About the project:

To become familiar with the VFS layer of Linux, and especially with extensible file systems APIs. To build a useful file system using stacking technologies. 
We have used the "wrapfs" stackable file system as a starting point for this assignment and modified wrapfs to add "secure trash-bin file system" (stbfs) support.

# Design Consideration
    PS: Root user behaves like an admin and has complete access to .stb dir and all its files.

    1. During mounting, I have taken the encryption key and the mount point of the lower file system
       in the super block of the mounted file system. This is done to improve the efficieny and to ease the development of unlink of stbfs. Before storing, I am checking if the length of password passed is greater than 6 characters, and if so, I am generating the SHA256 hash of the password 
       and storing it. 
       1.1 The changes done were in the struct stbfs_sb_info structure.
            I added the void *enckey; char *mount_point

    2. In stbfs_unlink, the naming convention followed to store the file in .stb directory is the following:
        2.1 <user_id>_<ts in ns>_<file_name>.enc [if enc key is passed]
        2.2 <user_id>_<ts in ns>_<file_name> [if enc key is not passed]
    
    3. In stbfs_unlink: [All operations are done on the lower fs dentry]
        3.1 For permanent deletion, we check if the parent dentry name is .stb and if the first part
            of the .stb file, i.e <user_id> matches with the current user_id  which I am getting using the get_current_user()->uid.val. If the conditions are met then directly go to the vfs_unlink function, which takes a lock on the parent dir inode and deletes the file. 
                
        3.2 For encryption (storing the file in .stb), I am encrypting the file using the hash stored in 
            super block and storing the hash of hash in the preamble, this way not compromising the 
            integrity of the file.
        3.3 If the hash stored in super block is NULL, then directly copy the contents of file without encryption.
    
    4. In ioclt to undelete the file. Command ./stbfsctl -u filename
        4.1 "filename" needs to be in the format defined in 2.1 or 2.2 
        4.2 Since the ioctl command accepts the fd of the file, command and arguments, from the user land code, I passed the fd of the cwd and the structure containg the file name to be deleted and
        the lenght of the file as arguments.
        4.3 Once the command and the arguments is received in the kernel, I use copy_from_user to fetch the args sturcture. Since the file to undelete has user id and ts and the file to restore the contents to should be the original file name, we do string manipulation inside the kernel code.
        4.4 For finding the absolute path of the "filename" to delete, we get the absolute path of the file wrt to the mounter dir (using dentry_path_raw) and append the mount point stored in super block. For getting the absolute path of the file to which the contents need to be restored to, I get the absolute path of I am again by first getting the cwd dir wrt to the mounted dir (b), puuting the mount point (a) in front of it and appending the string manipulated filename (c) to it. Therefore, the abs path is /a/b/c.
            4.4.1 The same logic applies to finding the abs paths of file in 3.
        4.5 Now that the file paths are received, we open the file using filp_open.

    5. For preventing the users to view others files in .stb dir, I made changes to readdir function by creating a new callback function which is part of dir context and adding the logic. The logic checks if the dentry is .stb, if so, then it checks the first part of the file with the current user id, if so allow the file to be displayed otherwise fall through and increment the next pointer.

    6. Similarly, for preventing chown, chmod, mkdir, rmdir, etc. functions on .stb dir or .stb files, I am checking if the dentry name is .stb or the parent denrty name is .stb, if so then check if the current user is root, if the conditions are met, then allow the operations else deny. To prevent for a particular file to ls'd in .stb, I follow the same approach as in 6. The changes are done in stbfs_lookup.

    7. Mounting command only taken the enc= option for parsing the enckey if required, the command is 
       mount -t stbfs -o enc=MySecretPa55 /test/src1/ /mnt/stbfs1/, /test/src1 is the ext4 fs, /mnt/stbfs1 is the upper fs. If no enc key is provided, the command is mount -t stbfs /test/src1/ /mnt/stbfs1/. COmmand to make the stbfs code is make stbfs-abc.



# Steps to reproduce the code and assumptions
    1. Git clone
    2. Make kernel and create fs/stbfs file
    3. Execute test0*.sh scripts
    4. stbfsctl command is always executed from some dir on the mounted dir. Ex, if mounter dir /mnt/stbfs, then the command needs to be run from /mnt/stbfs/*
    5. .stb needs to be created manually with (0777) permisssions, rwx for owner, group, others
    

# References
    1. Code of ecryptfs
    2. https://stackoverflow.com/questions/29458157/how-to-get-a-file-list-from-a-directory-inside-the-linux-kernel for fill_dir function
    3. MY HW1 Assignment for enc/dec
    4. Wrapfs code



    
    
