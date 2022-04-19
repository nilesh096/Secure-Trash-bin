// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 1998-2020 Erez Zadok
 * Copyright (c) 2009	   Shrikar Archak
 * Copyright (c) 2003-2020 Stony Brook University
 * Copyright (c) 2003-2020 The Research Foundation of SUNY
 */

#include "stbfs.h"
#define MAGIC 'U'
#define NUM 0
#define FS_STB_UNDELETE _IOR(MAGIC, NUM, unsigned long)

typedef struct argument {
	char *infile;
	int flen;
} arguments;

static ssize_t stbfs_read(struct file *file, char __user *buf,
			   size_t count, loff_t *ppos)
{
	int err;
	struct file *lower_file;
	struct dentry *dentry = file->f_path.dentry;

	lower_file = stbfs_lower_file(file);
	err = vfs_read(lower_file, buf, count, ppos);
	/* update our inode atime upon a successful lower read */
	if (err >= 0)
		fsstack_copy_attr_atime(d_inode(dentry),
					file_inode(lower_file));

	return err;
}

static ssize_t stbfs_write(struct file *file, const char __user *buf,
			    size_t count, loff_t *ppos)
{
	int err;

	struct file *lower_file;
	struct dentry *dentry = file->f_path.dentry;

	lower_file = stbfs_lower_file(file);
	err = vfs_write(lower_file, buf, count, ppos);
	/* update our inode times+sizes upon a successful lower write */
	if (err >= 0) {
		fsstack_copy_inode_size(d_inode(dentry),
					file_inode(lower_file));
		fsstack_copy_attr_times(d_inode(dentry),
					file_inode(lower_file));
	}

	return err;
}

struct stbfs_getdents_callback {
	struct dir_context ctx;
	struct dir_context *caller;
};

/*
Callback function for readdir
*/
static int stbfs_filldir(struct dir_context *ctx, const char *lower_name,
			 int lower_namelen, loff_t offset, u64 ino,
			 unsigned int d_type)
{
	int rc = 0;
	char *current_user = NULL;
	bool call = true;
	struct stbfs_getdents_callback *buf =
		container_of(ctx, struct stbfs_getdents_callback, ctx);

	current_user = (char *)kmalloc(8, GFP_KERNEL);
	if (current_user == NULL)
	{
		rc = -ENOMEM;
		goto out;
	}
	sprintf(current_user, "%d", get_current_user()->uid.val);
	
	if(strncmp(lower_name, current_user, strlen(current_user)) == 0)
	{
		call = false;
		pr_info("User is listing the files which he/she owns");
	}

out:
	if(current_user)
		kfree (current_user);
	if (call == false) {
		buf->caller->pos = buf->ctx.pos;
		rc = !dir_emit(buf->caller, lower_name, lower_namelen, ino, d_type);
	}
	return rc;
}


static int stbfs_readdir(struct file *file, struct dir_context *ctx)
{
	int err;
	struct file *lower_file = NULL;
	struct dentry *dentry = file->f_path.dentry;

	struct stbfs_getdents_callback buf = {
		.ctx.actor = stbfs_filldir, 
		.caller = ctx,
	};

	lower_file = stbfs_lower_file(file);
	if ((strcmp(dentry->d_iname,".stb") == 0)  
				&& (get_current_user()->uid.val != 0))
		err = iterate_dir(lower_file, &buf.ctx);		
	else
		err = iterate_dir(lower_file, ctx);
	
	file->f_pos = lower_file->f_pos;
	ctx->pos = buf.ctx.pos;
	if (err >= 0)		/* copy the atime */
		fsstack_copy_attr_atime(d_inode(dentry),
					file_inode(lower_file));
	return err;
}

/*
Get the file absolute path of the new file
*/
int get_new_file_abs_path (char **path_name, char *file_name, char *cwd, char *root_path)
{
	*path_name = (char *)kmalloc(PATH_MAX, GFP_KERNEL);
	if (*path_name == NULL)
		return -ENOMEM;
	memset(*path_name, '\0', PATH_MAX);
	sprintf(*path_name, "%s%s/%s", root_path, cwd, file_name);
	return 0;
}

/*
Function to get the file name to restore from the filename passed 
in user
*/
int get_new_file (char **file_name, char *original_name, void *enc_key)
{
	int ret = 0, count = 0, i = 0, j = 0;
	char *buf = NULL;
	bool is_valid = false;
	buf = (char *)kmalloc(NAME_MAX, GFP_KERNEL);
	if (buf == NULL)
	{
		ret = -ENOMEM;
		goto out_file_name;
	}
	*file_name = (char *)kmalloc(NAME_MAX, GFP_KERNEL);
	if (*file_name == NULL)
	{
		ret = -ENOMEM;
		goto out_file_name;
	}
	memset(buf, '\0', NAME_MAX);
	memset(*file_name, '\0', NAME_MAX);

	if (enc_key != NULL)
		memcpy(buf, original_name, strlen(original_name) - 4);
	else
		strcpy(buf, original_name);

	pr_info("Temp Name = %s", buf);

	for (i = 0; i < strlen(buf); i++)
	{
		if (is_valid)
		{
			(*file_name)[j] = buf[i];
			j += 1;
		}
		if (buf[i] == '_')
		{
			count += 1;		
			if (count == 2)
				is_valid = true;
		}
	}
	if (!is_valid)
	{
		ret = -1;
		goto out_file_name;
	}
	pr_info("Final file name is %s", *file_name);

out_file_name:
	if (buf)
	{
		pr_info("Cleanup: Freeing buffer to store the temporary file name");
		kfree(buf);
	}
	return ret;
}

/*
Function to allocate memory
*/
int mallock (char **buf, int len)
{
	*buf = (char *)kmalloc(len, GFP_KERNEL);
	if (*buf == NULL)
		return -ENOMEM;
	return 0;
}

/* 
Get the mount point from super block
*/
char *get_root_path (struct super_block *sb)
{
	return ((struct stbfs_sb_info *)(sb->s_fs_info))->mount_point;
}

/*
Function to delete the file
*/
int delete_file (struct inode *dir_inode, struct dentry *dentry)
{
	struct dentry *lock_parent_dir;
	int err = 0;

	lock_parent_dir = lock_parent(dentry);
	err = vfs_unlink(dir_inode, dentry, NULL);
	if (err < 0)
		pr_alert ("Failed to delete the file %s", dentry->d_iname);

	unlock_dir(lock_parent_dir);
	return err;
}

static long stbfs_unlocked_ioctl(struct file *file, unsigned int cmd,
				  unsigned long arg)
{
	long err = -ENOTTY;
	struct file *lower_file;
	arguments *karg = NULL;
	struct dentry *cwd_lower_dentry;
	struct path lower_path, root_path;
	char *cwd = NULL , *file_name = NULL, *new_file = NULL;
	char *new_abs_path = NULL;
	void *enc_key = NULL, *hash_cipher_key = NULL;
	unsigned char flag;
	struct file *og_fp = NULL, *new_fp = NULL; 

	lower_file = stbfs_lower_file(file);
	stbfs_get_lower_path(file->f_path.dentry, &lower_path);
	cwd_lower_dentry = lower_path.dentry;
	stbfs_get_lower_path(file->f_path.dentry->d_sb->s_root, &root_path);

	pr_info("Entered here");

	switch (cmd)
	{
		case FS_STB_UNDELETE:
			karg = (arguments *)kmalloc(sizeof(arguments), GFP_KERNEL);
			if (!karg) {
        		err = -ENOMEM;
        		goto out;
    		}
			karg->infile = NULL;

			if (copy_from_user(karg, (arguments *)(void __user *)arg, sizeof(arguments))) {
				err = -EFAULT;
				goto out;
			}
			pr_info("Copy from user of structure done");

			karg->infile = kmalloc(karg->flen + 1, GFP_KERNEL);
			if (karg->infile == NULL)
			{
				err = -ENOMEM;
				goto out;
			}
			memset(karg->infile, '\0', karg->flen + 1);

			if(copy_from_user(karg->infile, ((arguments *)(void __user *)arg)->infile, karg->flen + 1))
			{
				err = -EFAULT;
				goto out;
			}
			pr_info("Copy from user of input file done");

			pr_info("File Name is %s",karg->infile);
			pr_info("File length is %ld", strlen(karg->infile));

			if ((get_current_user()->uid.val != 0) &&
				(is_owner(file->f_path.dentry, karg->infile) != 0)) {
				err = -EACCES;
				pr_alert("Failure in trying to undelete file in .stb dir, access denied");
				goto out;
			}
			
			if (mallock(&cwd, PATH_MAX) < 0)
				goto out;
			
			err = get_absolute_path(file->f_path.dentry, cwd);
			pr_info("CUrrent working directory is %s", cwd);
			if (err < 0)
				goto out;
		

			enc_key = get_enc_key(file->f_path.dentry->d_sb);
			pr_info("Enc key is %s", (char *)enc_key);

			err = get_new_file(&new_file, karg->infile, enc_key);
			if (err < 0) {
				pr_alert("Invalid file provided");
				goto out;
			}
			pr_info("File name in calling function is %s", new_file);

			file_name = (char *)kmalloc(PATH_MAX, GFP_KERNEL);
			if (!file_name) {
				err = -ENOMEM;
				goto out;
			}
			memset(file_name, '\0', PATH_MAX);
			sprintf(file_name, "%s/.stb/%s", get_root_path(file->f_path.dentry->d_sb), karg->infile);
			pr_info("File to restore full path is %s", file_name);

			og_fp = filp_open(file_name, O_RDONLY, 0);
			if (IS_ERR(og_fp)) {
				err = PTR_ERR(og_fp);
				pr_alert("Input File %s can't be opened for reading\n", file_name);
				goto out;
			}
			
			err = get_new_file_abs_path(&new_abs_path, new_file, cwd, get_root_path(file->f_path.dentry->d_sb));
			if (err < 0)
				goto out;
			pr_info("Absolute path of new file is %s", new_abs_path);
			new_fp = filp_open(new_abs_path, O_CREAT|O_WRONLY, og_fp->f_path.dentry->d_inode->i_mode);
			if (IS_ERR(new_fp)) {
				err = PTR_ERR(new_fp);
				pr_alert("File %s to copy contents to can't be opened for writing\n", new_abs_path);
				goto out;
			}

			if (enc_key == NULL)
				flag = (unsigned char)0x04;
			else
			{
				flag = (unsigned char)0x02;
				hash_cipher_key = kmalloc(SHA256_LEN, GFP_KERNEL);
				if (hash_cipher_key == NULL) {
					err = -ENOMEM;
					goto out;
				}
				memset(hash_cipher_key, 0, SHA256_LEN);
				err = generate_hash((const u8 *)enc_key, SHA256_LEN, (u8 *)hash_cipher_key);
				if (err < 0)
					goto out;
				err = read_preamble(hash_cipher_key, og_fp);
				if (err < 0) {
					pr_alert("Failed to verify preamble in the output file\n");
					delete_file (new_fp->f_path.dentry->d_parent->d_inode, new_fp->f_path.dentry);
					goto out;
				}
			}
			pr_info("Starting read write");
			err = read_write(og_fp, new_fp, enc_key, flag);
			if(err < 0) {	
				pr_alert("Error in dec/copy");
				goto out;
			}

			err = delete_file (og_fp->f_path.dentry->d_parent->d_inode, og_fp->f_path.dentry);
			if (err < 0)
				goto out;
			pr_info("Unlink successful");

			break;
		
		default:
			if (!lower_file || !lower_file->f_op)
				goto out;
			if (lower_file->f_op->unlocked_ioctl)
				err = lower_file->f_op->unlocked_ioctl(lower_file, cmd, arg);

			/* some ioctls can change inode attributes (EXT2_IOC_SETFLAGS) */
			if (!err)
				fsstack_copy_attr_all(file_inode(file),
							file_inode(lower_file));

	}

	/* XXX: use vfs_ioctl if/when VFS exports it */

out:

	stbfs_put_lower_path(file->f_path.dentry, &lower_path);
	stbfs_put_lower_path(file->f_path.dentry->d_sb->s_root, &root_path);
	if (karg) {
		if (karg->infile) {
			pr_info("Cleanup: Freeing infile buffer\n");
			kfree(karg->infile);
		}
		pr_info("Cleanup: Freeing kernel structure to hold arguments\n");
		kfree(karg);
	}
	if (cwd != NULL) {
		pr_info("Cleanup: Freeing cwd buffer");
		kfree(cwd);
	}
	// if (root_path_name != NULL) {
	// 	pr_info("Cleanup: Freeing root path buffer");
	// 	kfree(root_path_name);
	// }
	if (file_name != NULL) {
		kfree(file_name);
	}
	if (new_file != NULL)
		kfree(new_file);
	if ((og_fp != NULL) && (!IS_ERR(og_fp))) {
		pr_info("Cleanup: Closing original file pointer");
		filp_close(og_fp, NULL);
	}
	if ((new_fp != NULL) && (!IS_ERR(new_fp))) {
		pr_info("Cleanup: Closing new file pointer");
		filp_close(new_fp, NULL);
	}
	if (new_abs_path != NULL)
		kfree(new_abs_path);
	if (hash_cipher_key != NULL)
		kfree(hash_cipher_key);
	return err;
}

#ifdef CONFIG_COMPAT
static long stbfs_compat_ioctl(struct file *file, unsigned int cmd,
				unsigned long arg)
{
	long err = -ENOTTY;
	struct file *lower_file;

	lower_file = stbfs_lower_file(file);

	/* XXX: use vfs_ioctl if/when VFS exports it */
	if (!lower_file || !lower_file->f_op)
		goto out;
	if (lower_file->f_op->compat_ioctl)
		err = lower_file->f_op->compat_ioctl(lower_file, cmd, arg);

out:
	return err;
}
#endif

static int stbfs_mmap(struct file *file, struct vm_area_struct *vma)
{
	int err = 0;
	bool willwrite;
	struct file *lower_file;
	const struct vm_operations_struct *saved_vm_ops = NULL;

	/* this might be deferred to mmap's writepage */
	willwrite = ((vma->vm_flags | VM_SHARED | VM_WRITE) == vma->vm_flags);

	/*
	 * File systems which do not implement ->writepage may use
	 * generic_file_readonly_mmap as their ->mmap op.  If you call
	 * generic_file_readonly_mmap with VM_WRITE, you'd get an -EINVAL.
	 * But we cannot call the lower ->mmap op, so we can't tell that
	 * writeable mappings won't work.  Therefore, our only choice is to
	 * check if the lower file system supports the ->writepage, and if
	 * not, return EINVAL (the same error that
	 * generic_file_readonly_mmap returns in that case).
	 */
	lower_file = stbfs_lower_file(file);
	if (willwrite && !lower_file->f_mapping->a_ops->writepage) {
		err = -EINVAL;
		printk(KERN_ERR "stbfs: lower file system does not "
		       "support writeable mmap\n");
		goto out;
	}

	/*
	 * find and save lower vm_ops.
	 *
	 * XXX: the VFS should have a cleaner way of finding the lower vm_ops
	 */
	if (!STBFS_F(file)->lower_vm_ops) {
		err = lower_file->f_op->mmap(lower_file, vma);
		if (err) {
			printk(KERN_ERR "stbfs: lower mmap failed %d\n", err);
			goto out;
		}
		saved_vm_ops = vma->vm_ops; /* save: came from lower ->mmap */
	}

	/*
	 * Next 3 lines are all I need from generic_file_mmap.  I definitely
	 * don't want its test for ->readpage which returns -ENOEXEC.
	 */
	file_accessed(file);
	vma->vm_ops = &stbfs_vm_ops;

	file->f_mapping->a_ops = &stbfs_aops; /* set our aops */
	if (!STBFS_F(file)->lower_vm_ops) /* save for our ->fault */
		STBFS_F(file)->lower_vm_ops = saved_vm_ops;

out:
	return err;
}

static int stbfs_open(struct inode *inode, struct file *file)
{
	int err = 0;
	struct file *lower_file = NULL;
	struct path lower_path;

	/* don't open unhashed/deleted files */
	if (d_unhashed(file->f_path.dentry)) {
		err = -ENOENT;
		goto out_err;
	}

	file->private_data =
		kzalloc(sizeof(struct stbfs_file_info), GFP_KERNEL);
	if (!STBFS_F(file)) {
		err = -ENOMEM;
		goto out_err;
	}

	/* open lower object and link stbfs's file struct to lower's */
	stbfs_get_lower_path(file->f_path.dentry, &lower_path);
	lower_file = dentry_open(&lower_path, file->f_flags, current_cred());
	path_put(&lower_path);
	if (IS_ERR(lower_file)) {
		err = PTR_ERR(lower_file);
		lower_file = stbfs_lower_file(file);
		if (lower_file) {
			stbfs_set_lower_file(file, NULL);
			fput(lower_file); /* fput calls dput for lower_dentry */
		}
	} else {
		stbfs_set_lower_file(file, lower_file);
	}

	if (err)
		kfree(STBFS_F(file));
	else
		fsstack_copy_attr_all(inode, stbfs_lower_inode(inode));
out_err:
	return err;
}

static int stbfs_flush(struct file *file, fl_owner_t id)
{
	int err = 0;
	struct file *lower_file = NULL;

	lower_file = stbfs_lower_file(file);
	if (lower_file && lower_file->f_op && lower_file->f_op->flush) {
		filemap_write_and_wait(file->f_mapping);
		err = lower_file->f_op->flush(lower_file, id);
	}

	return err;
}

/* release all lower object references & free the file info structure */
static int stbfs_file_release(struct inode *inode, struct file *file)
{
	struct file *lower_file;

	lower_file = stbfs_lower_file(file);
	if (lower_file) {
		stbfs_set_lower_file(file, NULL);
		fput(lower_file);
	}

	kfree(STBFS_F(file));
	return 0;
}

static int stbfs_fsync(struct file *file, loff_t start, loff_t end,
			int datasync)
{
	int err;
	struct file *lower_file;
	struct path lower_path;
	struct dentry *dentry = file->f_path.dentry;

	err = __generic_file_fsync(file, start, end, datasync);
	if (err)
		goto out;
	lower_file = stbfs_lower_file(file);
	stbfs_get_lower_path(dentry, &lower_path);
	err = vfs_fsync_range(lower_file, start, end, datasync);
	stbfs_put_lower_path(dentry, &lower_path);
out:
	return err;
}

static int stbfs_fasync(int fd, struct file *file, int flag)
{
	int err = 0;
	struct file *lower_file = NULL;

	lower_file = stbfs_lower_file(file);
	if (lower_file->f_op && lower_file->f_op->fasync)
		err = lower_file->f_op->fasync(fd, lower_file, flag);

	return err;
}

/*
 * Wrapfs cannot use generic_file_llseek as ->llseek, because it would
 * only set the offset of the upper file.  So we have to implement our
 * own method to set both the upper and lower file offsets
 * consistently.
 */
static loff_t stbfs_file_llseek(struct file *file, loff_t offset, int whence)
{
	int err;
	struct file *lower_file;

	err = generic_file_llseek(file, offset, whence);
	if (err < 0)
		goto out;

	lower_file = stbfs_lower_file(file);
	err = generic_file_llseek(lower_file, offset, whence);

out:
	return err;
}

/*
 * Wrapfs read_iter, redirect modified iocb to lower read_iter
 */
ssize_t
stbfs_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	int err;
	struct file *file = iocb->ki_filp, *lower_file;

	lower_file = stbfs_lower_file(file);
	if (!lower_file->f_op->read_iter) {
		err = -EINVAL;
		goto out;
	}

	get_file(lower_file); /* prevent lower_file from being released */
	iocb->ki_filp = lower_file;
	err = lower_file->f_op->read_iter(iocb, iter);
	iocb->ki_filp = file;
	fput(lower_file);
	/* update upper inode atime as needed */
	if (err >= 0 || err == -EIOCBQUEUED)
		fsstack_copy_attr_atime(d_inode(file->f_path.dentry),
					file_inode(lower_file));
out:
	return err;
}

/*
 * Wrapfs write_iter, redirect modified iocb to lower write_iter
 */
ssize_t
stbfs_write_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	int err;
	struct file *file = iocb->ki_filp, *lower_file;

	lower_file = stbfs_lower_file(file);
	if (!lower_file->f_op->write_iter) {
		err = -EINVAL;
		goto out;
	}

	get_file(lower_file); /* prevent lower_file from being released */
	iocb->ki_filp = lower_file;
	err = lower_file->f_op->write_iter(iocb, iter);
	iocb->ki_filp = file;
	fput(lower_file);
	/* update upper inode times/sizes as needed */
	if (err >= 0 || err == -EIOCBQUEUED) {
		fsstack_copy_inode_size(d_inode(file->f_path.dentry),
					file_inode(lower_file));
		fsstack_copy_attr_times(d_inode(file->f_path.dentry),
					file_inode(lower_file));
	}
out:
	return err;
}

const struct file_operations stbfs_main_fops = {
	.llseek		= generic_file_llseek,
	.read		= stbfs_read,
	.write		= stbfs_write,
	.unlocked_ioctl	= stbfs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= stbfs_compat_ioctl,
#endif
	.mmap		= stbfs_mmap,
	.open		= stbfs_open,
	.flush		= stbfs_flush,
	.release	= stbfs_file_release,
	.fsync		= stbfs_fsync,
	.fasync		= stbfs_fasync,
	.read_iter	= stbfs_read_iter,
	.write_iter	= stbfs_write_iter,
};

/* trimmed directory options */
const struct file_operations stbfs_dir_fops = {
	.llseek		= stbfs_file_llseek,
	.read		= generic_read_dir,
	.iterate	= stbfs_readdir,
	.unlocked_ioctl	= stbfs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= stbfs_compat_ioctl,
#endif
	.open		= stbfs_open,
	.release	= stbfs_file_release,
	.flush		= stbfs_flush,
	.fsync		= stbfs_fsync,
	.fasync		= stbfs_fasync,
};
