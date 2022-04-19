// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 1998-2020 Erez Zadok
 * Copyright (c) 2009	   Shrikar Archak
 * Copyright (c) 2003-2020 Stony Brook University
 * Copyright (c) 2003-2020 The Research Foundation of SUNY
 */

#include "stbfs.h"
#include <linux/string.h>
#include <linux/timekeeping.h>
#include <linux/sched.h>
#include <asm/current.h>
#include <linux/limits.h>
#include <crypto/hash.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <crypto/skcipher.h>
#include <linux/uaccess.h>
#include <linux/slab.h>


static int stbfs_create(struct inode *dir, struct dentry *dentry,
			 umode_t mode, bool want_excl)
{
	int err;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct path lower_path;

	stbfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_parent_dentry = lock_parent(lower_dentry);

	err = vfs_create(d_inode(lower_parent_dentry), lower_dentry, mode,
			 want_excl);
	if (err)
		goto out;
	err = stbfs_interpose(dentry, dir->i_sb, &lower_path);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, stbfs_lower_inode(dir));
	fsstack_copy_inode_size(dir, d_inode(lower_parent_dentry));

out:
	unlock_dir(lower_parent_dentry);
	stbfs_put_lower_path(dentry, &lower_path);
	return err;
}

/*
 Function to check if the command or operations needs to allowed
 for root or non-root users
*/

int is_cmd_allowed (struct dentry *dentry)
{
	if (((strcmp(dentry->d_iname,".stb") == 0) || (strcmp(dentry->d_parent->d_iname,".stb") == 0))
			&& (get_current_user()->uid.val != 0))
	{
		pr_alert("Non root user trying to modify .stb dir or file in .stb");
		return -EPERM;
	}
	pr_info("Root trying the operation");
	return 0;
}

static int stbfs_link(struct dentry *old_dentry, struct inode *dir,
		       struct dentry *new_dentry)
{
	struct dentry *lower_old_dentry;
	struct dentry *lower_new_dentry;
	struct dentry *lower_dir_dentry;
	u64 file_size_save;
	int err;
	struct path lower_old_path, lower_new_path;

	file_size_save = i_size_read(d_inode(old_dentry));
	stbfs_get_lower_path(old_dentry, &lower_old_path);
	stbfs_get_lower_path(new_dentry, &lower_new_path);
	lower_old_dentry = lower_old_path.dentry;
	lower_new_dentry = lower_new_path.dentry;
	lower_dir_dentry = lock_parent(lower_new_dentry);

	pr_info("In stbfs_link");
	err = is_cmd_allowed (old_dentry);
	if (err < 0)
		goto out;

	err = vfs_link(lower_old_dentry, d_inode(lower_dir_dentry),
		       lower_new_dentry, NULL);
	if (err || d_really_is_negative(lower_new_dentry))
		goto out;

	err = stbfs_interpose(new_dentry, dir->i_sb, &lower_new_path);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, d_inode(lower_new_dentry));
	fsstack_copy_inode_size(dir, d_inode(lower_new_dentry));
	set_nlink(d_inode(old_dentry),
		  stbfs_lower_inode(d_inode(old_dentry))->i_nlink);
	i_size_write(d_inode(new_dentry), file_size_save);
out:
	unlock_dir(lower_dir_dentry);
	stbfs_put_lower_path(old_dentry, &lower_old_path);
	stbfs_put_lower_path(new_dentry, &lower_new_path);
	return err;
}

/**
 * verify_preamble - Compare the input file preamble with cipher key 
 *
 * @buf1:       buffer containing the cipher key 
 * @buf2:       buffer containing the input file preamble
 *
 * This is a function to check whether the preamble matches the
 * cipher key
 * 
 * Retrun true if the preamble matches the cipher key
 * Return false if there is a mismatch 
 * 
 */
bool verify_preamble(const void *buf1, const void *buf2)
{
	return memcmp(buf1, buf2, SHA256_LEN) == 0;
}

/**
 * read_preamble - Read the input file preamble which is 32 bytes 
 *
 * @buf:        buffer containing the cipher key
 * @input:      struct file which is a file descriptor of the 
 * 				input file
 *
 * This is a function to read the preamble from the input file 
 * and compare it with the cipher key (verify_preamble function)
 * 
 * Retrun 0 if the reading of the preamble is successful and 
 * 			matches with the cipher key
 * Return -ve value if reading fails or cipher key doesn't match the preamble
 * 
 */
int read_preamble(void *buf, struct file *input)
{
	int err = 0;
	void *rbuf = NULL;

	rbuf = kmalloc(SHA256_LEN, GFP_KERNEL);

	if (rbuf == NULL) {
		err = -ENOMEM;
		goto out_read;
	}

	err = kernel_read(input, rbuf, SHA256_LEN, &input->f_pos);
	if (err < 0)
		goto out_read;


	if (!verify_preamble(buf, rbuf)) {
		pr_alert("Preamble mismatch\n");
		err = -EACCES;
		goto out_read;
	}

out_read:
	if (rbuf) {
		pr_debug("Freeing read buffer for reading preamble");
		kfree(rbuf);
	}
	return err;
}

/**
 * write_preamble - write the cipher key to the temp file 
 *
 * @buf:        buffer containing the cipher key
 * @output:     struct file which is a file descriptor of the 
 * 				temporary file
 *
 * This is a function to write the preamble (cipher key) into the temporary file
 * 
 * Retrun 0 if successfully able to write the preamble
 * Return -ve value if error in writing preamble
 * 
 */
int write_preamble(void *buf, struct file *output)
{
	ssize_t wbytes = 0;
	
	wbytes = kernel_write(output, buf, SHA256_LEN, &output->f_pos);
	pr_info("Preamble Bytes written = %ld\n", wbytes);

	if (wbytes < 0) 
		return wbytes;

	return 0;
}

int generate_hash_unlink(const u8 *input, unsigned int hash_length, u8 *output)
{
	int err = 0;
	struct shash_desc *desc = NULL;
	struct crypto_shash *alg = NULL;
	const char *hash_algo = "sha256";

	alg = crypto_alloc_shash(hash_algo, 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(alg)) {
		pr_alert("crypto_alloc_shash failed\n");
		err = PTR_ERR(alg);
		goto out_hash;
	}

	desc = kmalloc(crypto_shash_descsize(alg) + sizeof(*desc), GFP_KERNEL);
	if (desc == NULL) {
		err = -ENOMEM;
		goto out_hash;
	}

	desc->tfm = alg;

	err = crypto_shash_digest(desc, input, hash_length, output);
	if (err < 0) {
		pr_alert("Failed to generate digest\n");
		goto out_hash;
	}
	
out_hash:
	if (desc != NULL) {
		pr_info("Cleanup: Freeing struct shash_desc\n");
		desc->tfm = NULL;
		kfree(desc);
	}
	if ((alg != NULL) && (!IS_ERR(alg))) {
		pr_info("Cleanup: Freeing hash algo struct\n");
		crypto_free_shash(alg);
	}
	return err;
}

/*
Returns the enc key stored in super block
*/
void* get_enc_key(struct super_block *sb)
{
	return ((struct stbfs_sb_info *)(sb->s_fs_info))->enckey;
}

/*
Uses dentry_path_raw to get the absolute path of the file
*/
int get_absolute_path(struct dentry *dentry, char *file_path)
{
	int ret = 0;
	char *val;
	char *buf = NULL;
	buf = (char *)kmalloc(PATH_MAX, GFP_KERNEL);
	if (buf == NULL)
	{
		ret = -ENOMEM;
		goto out_fp;
	}

	val = dentry_path_raw(dentry, buf, PATH_MAX);
	if (IS_ERR(val))
	{
		pr_alert("Error in getting the path name");
		ret = PTR_ERR(val);
		goto out_fp;
	}
	strcpy(file_path, val);
	// if (get_current_user()->uid.val != 0)
	// 	strcat(file_path,"/home");

out_fp:
	if (buf != NULL)
	{
		pr_info("Cleanup: Freeing buffer");
		kfree(buf);
		val = NULL;
	}
	return ret;
}

/**
 * encdec - do encryption/decryption of the file based on the flag
 *
 * @iv:         iv data 
 * @req:     	struct skcipher_request holds all information needed
 *              to perform the cipher operation
 * @buf:        buffer containing the data to encrypt/decrypt
 * @buf_len:    length of bytes to  encrypt/decrypt
 * @sg:         struct sctterlist
 * @wait:       A helper struct for waiting for completion of async crypto operation
 * @flag:       conatins info to decrypt/encrypt
 * 
 *
 * This is a function to encrypt/decrypt the file with AES encryption 
 * in CTR mode (symmetric key cryptography)
 * 
 * Return the value from crypto_wait_req operation
 * 
 */
static int encdec(char *iv, struct skcipher_request *req, 
				void *buf, int buf_len, struct scatterlist *sg,
				struct crypto_wait *wait, unsigned int flag)
{
	int ret = 0;

	skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG, crypto_req_done, wait);
	sg_init_one(sg, buf, buf_len);
	skcipher_request_set_crypt(req, sg, sg, buf_len, iv);
	crypto_init_wait(wait);

	if (flag & 0x01)
		ret = crypto_wait_req(crypto_skcipher_encrypt(req), wait);
	else
		ret = crypto_wait_req(crypto_skcipher_decrypt(req), wait);

	return ret;
}


/**
 * read_write - do read/write to/from a file;
 * 				encrypt the file if flag is 0x01
 * 				decrypt if flag is 0x02
 * 				just copy if flag is 0x04	
 *
 * @input:      struct file which the file descriptor of the input file
 * @req:     	struct file which the file descriptor of the output file
 * @key:        buffer containing the cipher key
 * @flag:    	flag to encrypt/decrypt/copy
 *
 * This is a function to read_write form/to a file 
 * and do encryption/decryption/copy based on flag value
 * 
 * Return 0 if read/write successful
 * Return -ve val if any operation fails
 */
int read_write(struct file *input, struct file *output, 
				void *key, unsigned int flag) 
{

	ssize_t read_bytes = 0, write_bytes = 0;
	int err = 0;
	struct crypto_skcipher *skcipher = NULL;
	struct skcipher_request *req = NULL;
	char *ivdata = NULL;
	void *buf = kmalloc(PAGE_SIZE, GFP_KERNEL);

	if (buf == NULL) {
		err = -ENOMEM;
		goto out_rw;
	}

	pr_info("Able to allocate memory for read buffer");

	if (!(!(flag & 0x01) && !(flag & 0x02))) {
		skcipher = crypto_alloc_skcipher("ctr-aes-aesni", 0, 0);
    	if (IS_ERR(skcipher)) {
        	pr_alert("ERROR: Failed to create skcipher handle\n");
        	err =  PTR_ERR(skcipher);
			goto out_rw;
    	}

		req = skcipher_request_alloc(skcipher, GFP_KERNEL);
    	if (req == NULL) {
        	pr_alert("Failed to allocate skcipher request\n");
        	err = -ENOMEM;
        	goto out_rw;
    	}

		ivdata = (char *)kmalloc(16, GFP_KERNEL);
    	if (!ivdata) {
        	pr_alert("Failed to allocate ivdata\n");
        	goto out_rw;
    	}
		memset(ivdata, 98765, 16);

		if (crypto_skcipher_setkey(skcipher, key, SHA256_LEN)) {
			pr_alert("Error in setting key in skcipher\n");
			err = -EAGAIN;
			goto out_rw;
		}
	}

	while ((read_bytes = kernel_read(input, buf, PAGE_SIZE, &input->f_pos)) > 0) {
		if (flag & 0x01 || flag & 0x02) {
			struct scatterlist *sg = NULL;
			struct crypto_wait *wait = NULL;

			sg = (struct scatterlist *)kmalloc(sizeof(struct scatterlist), GFP_KERNEL);
			if (!sg) {
				err = -ENOMEM;
				pr_alert("ERROR: Error in allocating memory for scatterlist\n");
				goto out_rw;
			}
			wait = (struct crypto_wait *)kmalloc(sizeof(struct crypto_wait), GFP_KERNEL);
			if (!wait) {
				err = -ENOMEM;
				pr_alert("ERROR: Error in allocating memory for crypto_wait\n");
				kfree(sg);
				goto out_rw;
			}

			err = encdec(ivdata, req, buf, read_bytes, sg, wait, flag);
			kfree(wait);
			wait = NULL;
			kfree(sg);
			sg = NULL;
		
			if (err < 0) {
				if (flag & 0x01) {
					pr_alert("ERROR: Encryption operation failed\n");
					goto out_rw;
				} else {
					pr_alert("ERROR: Decryption operation failed\n");
					goto out_rw;
				}
			}
		}

		write_bytes = kernel_write(output, buf, read_bytes, &output->f_pos);
		pr_info("Bytes written = %ld\n", write_bytes);

		if (write_bytes < 0) {
			pr_alert("Error in writing data to output file\n");
			err = write_bytes;
			goto out_rw;
		}
	}

out_rw:
	if (buf) {
		pr_info("Cleanup: Cleaning buffer for read");
		kfree(buf);
	}

	if ((skcipher != NULL) && (!IS_ERR(skcipher)))
	{
		pr_info("Cleanup: Cleaning up skcipher");
		crypto_free_skcipher(skcipher);
	}

	if (req) {
		pr_info("Cleanup: Cleaning up request");
        skcipher_request_free(req);
	}

	if (ivdata) {
		pr_info("Cleanup: Cleaning up ivdata");
        kfree(ivdata);
	}
	return err;
}

/*
	Get utc ts in ns
*/
long get_utc_time(void)
{
	struct timespec64 now;
	ktime_get_ts64(&now);
	return now.tv_nsec;
}

/*
	Function to check if the current userid matches the first part
	in .stb 
*/
int is_owner (struct dentry *dentry, char *name)
{
	char *user_id = NULL;
	int ret = 0;
	
	user_id = (char *)kmalloc(8, GFP_KERNEL);
	if (user_id == NULL)
	{
		ret = -ENOMEM;
		goto out_del;
	}

	sprintf(user_id, "%d", get_current_user()->uid.val);
	if (name == NULL)
		ret = strncmp(user_id, dentry->d_name.name, strlen(user_id));
	else
		ret = strncmp(user_id, name, strlen(user_id));

	if (ret != 0)
	{
		pr_alert("User %s trying to lookup/undelete/delete file which he doesn't own", user_id);
		ret = -EPERM;
		goto out_del;
	}

out_del:
 	if (user_id)
 	{
 		pr_info("Cleanup: Freeing memory for user_id buffer");
 		kfree(user_id);
 	}
	return ret;
}

static int stbfs_unlink(struct inode *dir, struct dentry *dentry)
{
	int err = 0, filename_length;
	bool flag_lock = false;
	unsigned char flag; 
	char *file_path_name = NULL, *root_path_name = NULL, *stb_file_name = NULL, *file_full_path = NULL;
	void *enc_key = NULL, *hash_cipher_key = NULL;
	struct dentry *lower_dentry;
	struct inode *lower_dir_inode = stbfs_lower_inode(dir);
	struct dentry *lower_dir_dentry;
	struct path lower_path, root_path;
	struct file *file_tb_del = NULL, *kinfile_enc = NULL;
	long utc_time;

	stbfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	stbfs_get_lower_path(dentry->d_sb->s_root, &root_path);

	if (strcmp(dentry->d_parent->d_iname, ".stb") == 0)
	{
		if ((get_current_user()->uid.val == 0) ||
			(is_owner (lower_dentry, NULL) == 0)) {
			pr_info("Permanently deleting file %s", lower_dentry->d_name.name);
			goto out_unlink;
		} else {
			err = -EPERM;
			pr_alert("Failure in trying to delete file in .stb dir");
			goto out;
		}
	}
	

	file_path_name = (char *)kmalloc(PATH_MAX, GFP_KERNEL);
	if (file_path_name == NULL) {
		err = -ENOMEM;
		goto out;
	}

	file_full_path = (char *)kmalloc(PATH_MAX, GFP_KERNEL);
	if (file_full_path == NULL) {
		err = -ENOMEM;
		goto out;
	}
	memset(file_full_path, '\0', PATH_MAX);
	
	stb_file_name = (char *)kmalloc(PATH_MAX, GFP_KERNEL);
	if (stb_file_name == NULL) {
		err = -ENOMEM;
		goto out;
	}
	hash_cipher_key = kmalloc(SHA256_LEN, GFP_KERNEL);
	if (hash_cipher_key == NULL) {
		err = -ENOMEM;
		goto out;
	}
	enc_key = get_enc_key(dentry->d_sb);

	
	err = get_absolute_path(dentry, file_path_name);

	if (err < 0)
		goto out;
	pr_info("File to be deleted is %s", file_path_name);

	
	root_path_name = ((struct stbfs_sb_info *)(dentry->d_sb->s_fs_info))->mount_point;
	pr_info("Root path of lower fs is %s", root_path_name);

	utc_time = get_utc_time();
	
	filename_length = strlen(dentry->d_iname) + sizeof(d_inode(dentry)->i_uid.val) + sizeof(utc_time) + 6;
	if (filename_length > NAME_MAX) {
		err = -ENAMETOOLONG;
		pr_alert("File name too long");
		goto out;
	}
	if (filename_length + 6 + strlen(root_path_name) > PATH_MAX) {
		err = -ENAMETOOLONG;
		pr_alert("Path name too long");
		goto out;
	}
	sprintf(file_full_path, "%s%s", root_path_name, file_path_name);
	pr_info("Absolute File to be deleted is %s", file_full_path);

	
	if (enc_key != NULL)
		sprintf(stb_file_name, "%s/.stb/%d_%ld_%s.enc", root_path_name, 
							d_inode(dentry)->i_uid.val, utc_time, dentry->d_iname);
	else
		sprintf(stb_file_name, "%s/.stb/%d_%ld_%s", root_path_name, 
							d_inode(dentry)->i_uid.val, utc_time, dentry->d_iname);
	pr_info("Enc File name is %s", stb_file_name);

	file_tb_del = filp_open(file_full_path, O_RDONLY, dentry->d_inode->i_mode);
	if (IS_ERR(file_tb_del)) {
		err = PTR_ERR(file_tb_del);
		pr_alert("Input File %s can't be opened for reading\n", file_full_path);
		goto out;
	}
	pr_info("Input file %s opened successfully", file_full_path);

	//kinfile_enc = filp_open(stb_file_name, O_CREAT|O_WRONLY, dentry->d_inode->i_mode);
	kinfile_enc = filp_open(stb_file_name, O_CREAT|O_WRONLY, 0777);
	if (IS_ERR(kinfile_enc)) {
		err = PTR_ERR(kinfile_enc);
		pr_alert("Unable to create enc file\n");
		goto out;
	}
	pr_info("Enc file %s opened successfully", stb_file_name);

	
	pr_info("Enc key is %s", (char *)enc_key);
	if (enc_key == NULL)
		flag = (unsigned char)0x04;
	else {
		pr_info("Entered here");
		flag = (unsigned char)0x01;
		memset(hash_cipher_key, 0, SHA256_LEN);
		err = generate_hash_unlink((const u8 *)enc_key, SHA256_LEN, (u8 *)hash_cipher_key);
		if (err < 0)
			goto out;
		pr_info("Hash cipher key is %s", (char *)hash_cipher_key);
		err = write_preamble(hash_cipher_key, kinfile_enc);
		
		if (err < 0) {
			pr_alert("Failed to write preamble in the output file\n");
			
			goto out;
		}
	}

	pr_info("Starting read write");
	err = read_write(file_tb_del, kinfile_enc, enc_key, flag);
	if(err < 0) {
		//TODO: delete file
		pr_alert("Error in enc/copy");
		goto out;
	}

out_unlink:
	dget(lower_dentry);
	lower_dir_dentry = lock_parent(lower_dentry);
	flag_lock = true;
	if (lower_dentry->d_parent != lower_dir_dentry ||
	    d_unhashed(lower_dentry)) {
		err = -EINVAL;
		goto out;
	}

	err = vfs_unlink(lower_dir_inode, lower_dentry, NULL);

	/*
	 * Note: unlinking on top of NFS can cause silly-renamed files.
	 * Trying to delete such files results in EBUSY from NFS
	 * below.  Silly-renamed files will get deleted by NFS later on, so
	 * we just need to detect them here and treat such EBUSY errors as
	 * if the upper file was successfully deleted.
	 */
	if (err == -EBUSY && lower_dentry->d_flags & DCACHE_NFSFS_RENAMED)
		err = 0;
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, lower_dir_inode);
	fsstack_copy_inode_size(dir, lower_dir_inode);
	set_nlink(d_inode(dentry),
		  stbfs_lower_inode(d_inode(dentry))->i_nlink);
	d_inode(dentry)->i_ctime = dir->i_ctime;
	d_drop(dentry); /* this is needed, else LTP fails (VFS won't do it) */
out:
	if (flag_lock) {
		pr_info("Cleanup: Unlock the paernt dir");
		unlock_dir(lower_dir_dentry);
		dput(lower_dentry);
	}
	stbfs_put_lower_path(dentry->d_sb->s_root, &root_path);
	stbfs_put_lower_path(dentry, &lower_path);

	if (file_path_name != NULL) {
		pr_info("Cleanup: Deleting file path buffer");
		kfree(file_path_name);
	}
	if (stb_file_name != NULL) {
		pr_info("Cleanup: Deleting stb file path buffer");
		kfree(stb_file_name);
	}
	
	
	if (file_full_path != NULL) {
		pr_info("Cleanup: Freeing memory for file full path\n");
		kfree(file_full_path);
	}
	if (hash_cipher_key != NULL) {
		pr_info("Cleanup: Freeing memory for hashed key which contains the hash of the hash key\n");
		kfree(hash_cipher_key);
	}
	if ((file_tb_del != NULL) && (!IS_ERR(file_tb_del))) {
		pr_info("Cleanup: Closing file to be deleted");
    	filp_close(file_tb_del, NULL);
	}
	if ((kinfile_enc != NULL) && (!IS_ERR(kinfile_enc))) {
		pr_info("Cleanup: Closing enc file");
		filp_close(kinfile_enc, NULL);
	}
	return err;
}

static int stbfs_symlink(struct inode *dir, struct dentry *dentry,
			  const char *symname)
{
	int err;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct path lower_path;

	stbfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_parent_dentry = lock_parent(lower_dentry);

	pr_info("Entered inside symlink function");
	err = is_cmd_allowed (dentry);
	if (err < 0)
		goto out;

	err = vfs_symlink(d_inode(lower_parent_dentry), lower_dentry, symname);
	if (err)
		goto out;
	err = stbfs_interpose(dentry, dir->i_sb, &lower_path);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, stbfs_lower_inode(dir));
	fsstack_copy_inode_size(dir, d_inode(lower_parent_dentry));

out:
	unlock_dir(lower_parent_dentry);
	stbfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int stbfs_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	int err;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct path lower_path;

	stbfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_parent_dentry = lock_parent(lower_dentry);

	pr_info("Entered inside mkdir function");
	err = is_cmd_allowed (dentry);
	if (err < 0)
		goto out;

	err = vfs_mkdir(d_inode(lower_parent_dentry), lower_dentry, mode);
	if (err)
		goto out;

	err = stbfs_interpose(dentry, dir->i_sb, &lower_path);
	if (err)
		goto out;

	fsstack_copy_attr_times(dir, stbfs_lower_inode(dir));
	fsstack_copy_inode_size(dir, d_inode(lower_parent_dentry));
	/* update number of links on parent directory */
	set_nlink(dir, stbfs_lower_inode(dir)->i_nlink);

out:
	unlock_dir(lower_parent_dentry);
	stbfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int stbfs_rmdir(struct inode *dir, struct dentry *dentry)
{
	struct dentry *lower_dentry;
	struct dentry *lower_dir_dentry;
	int err;
	struct path lower_path;

	stbfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_dir_dentry = lock_parent(lower_dentry);
	if (lower_dentry->d_parent != lower_dir_dentry ||
	    d_unhashed(lower_dentry)) {
		err = -EINVAL;
		goto out;
	}

	pr_info("Entered inside rmdir function");
	err = is_cmd_allowed (dentry);
	if (err < 0)
		goto out;
	

	err = vfs_rmdir(d_inode(lower_dir_dentry), lower_dentry);
	if (err)
		goto out;

	d_drop(dentry);	/* drop our dentry on success (why not VFS's job?) */
	if (d_inode(dentry))
		clear_nlink(d_inode(dentry));
	fsstack_copy_attr_times(dir, d_inode(lower_dir_dentry));
	fsstack_copy_inode_size(dir, d_inode(lower_dir_dentry));
	set_nlink(dir, d_inode(lower_dir_dentry)->i_nlink);

out:
	unlock_dir(lower_dir_dentry);
	stbfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int stbfs_mknod(struct inode *dir, struct dentry *dentry, umode_t mode,
			dev_t dev)
{
	int err;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct path lower_path;

	stbfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_parent_dentry = lock_parent(lower_dentry);

	err = vfs_mknod(d_inode(lower_parent_dentry), lower_dentry, mode, dev);
	if (err)
		goto out;

	err = stbfs_interpose(dentry, dir->i_sb, &lower_path);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, stbfs_lower_inode(dir));
	fsstack_copy_inode_size(dir, d_inode(lower_parent_dentry));

out:
	unlock_dir(lower_parent_dentry);
	stbfs_put_lower_path(dentry, &lower_path);
	return err;
}

/*
 * The locking rules in stbfs_rename are complex.  We could use a simpler
 * superblock-level name-space lock for renames and copy-ups.
 */
static int stbfs_rename(struct inode *old_dir, struct dentry *old_dentry,
			 struct inode *new_dir, struct dentry *new_dentry,
			 unsigned int flags)
{
	int err = 0;
	struct dentry *lower_old_dentry = NULL;
	struct dentry *lower_new_dentry = NULL;
	struct dentry *lower_old_dir_dentry = NULL;
	struct dentry *lower_new_dir_dentry = NULL;
	struct dentry *trap = NULL;
	struct path lower_old_path, lower_new_path;

	if (flags)
		return -EINVAL;

	stbfs_get_lower_path(old_dentry, &lower_old_path);
	stbfs_get_lower_path(new_dentry, &lower_new_path);
	lower_old_dentry = lower_old_path.dentry;
	lower_new_dentry = lower_new_path.dentry;
	lower_old_dir_dentry = dget_parent(lower_old_dentry);
	lower_new_dir_dentry = dget_parent(lower_new_dentry);

	trap = lock_rename(lower_old_dir_dentry, lower_new_dir_dentry);
	pr_info("Parent dir name is %s", lower_old_dir_dentry->d_iname);
	pr_info("Dentry name is %s",lower_old_dentry->d_iname);

	err = is_cmd_allowed(old_dentry);

	if (err < 0)
		goto out;

	err = is_cmd_allowed(old_dentry);
	if (err < 0)
		goto out;


	err = -EINVAL;
	/* check for unexpected namespace changes */
	if (lower_old_dentry->d_parent != lower_old_dir_dentry)
		goto out;
	if (lower_new_dentry->d_parent != lower_new_dir_dentry)
		goto out;
	/* check if either dentry got unlinked */
	if (d_unhashed(lower_old_dentry) || d_unhashed(lower_new_dentry))
		goto out;
	/* source should not be ancestor of target */
	if (trap == lower_old_dentry)
		goto out;
	/* target should not be ancestor of source */
	if (trap == lower_new_dentry) {
		err = -ENOTEMPTY;
		goto out;
	}

	err = vfs_rename(d_inode(lower_old_dir_dentry), lower_old_dentry,
			 d_inode(lower_new_dir_dentry), lower_new_dentry,
			 NULL, 0);
	if (err)
		goto out;

	fsstack_copy_attr_all(new_dir, d_inode(lower_new_dir_dentry));
	fsstack_copy_inode_size(new_dir, d_inode(lower_new_dir_dentry));
	if (new_dir != old_dir) {
		fsstack_copy_attr_all(old_dir,
				      d_inode(lower_old_dir_dentry));
		fsstack_copy_inode_size(old_dir,
					d_inode(lower_old_dir_dentry));
	}

out:
	unlock_rename(lower_old_dir_dentry, lower_new_dir_dentry);
	dput(lower_old_dir_dentry);
	dput(lower_new_dir_dentry);
	stbfs_put_lower_path(old_dentry, &lower_old_path);
	stbfs_put_lower_path(new_dentry, &lower_new_path);
	return err;
}

static const char *stbfs_get_link(struct dentry *dentry, struct inode *inode,
				   struct delayed_call *done)
{
	DEFINE_DELAYED_CALL(lower_done);
	struct dentry *lower_dentry;
	struct path lower_path;
	char *buf;
	const char *lower_link;

	if (!dentry)
		return ERR_PTR(-ECHILD);

	stbfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;

	/*
	 * get link from lower file system, but use a separate
	 * delayed_call callback.
	 */
	lower_link = vfs_get_link(lower_dentry, &lower_done);
	if (IS_ERR(lower_link)) {
		buf = ERR_CAST(lower_link);
		goto out;
	}

	/*
	 * we can't pass lower link up: have to make private copy and
	 * pass that.
	 */
	buf = kstrdup(lower_link, GFP_KERNEL);
	do_delayed_call(&lower_done);
	if (!buf) {
		buf = ERR_PTR(-ENOMEM);
		goto out;
	}

	fsstack_copy_attr_atime(d_inode(dentry), d_inode(lower_dentry));

	set_delayed_call(done, kfree_link, buf);
out:
	stbfs_put_lower_path(dentry, &lower_path);
	return buf;
}

static int stbfs_permission(struct inode *inode, int mask)
{
	struct inode *lower_inode;
	int err;

	lower_inode = stbfs_lower_inode(inode);
	err = inode_permission(lower_inode, mask);
	return err;
}

static int stbfs_setattr(struct dentry *dentry, struct iattr *ia)
{
	int err;
	struct dentry *lower_dentry;
	struct inode *inode;
	struct inode *lower_inode;
	struct path lower_path;
	struct iattr lower_ia;

	inode = d_inode(dentry);
	pr_info("Setattr dentry name is %s", dentry->d_iname);
	err = is_cmd_allowed (dentry);
	if (err < 0)
		goto out_err;

	/*
	 * Check if user has permission to change inode.  We don't check if
	 * this user can change the lower inode: that should happen when
	 * calling notify_change on the lower inode.
	 */
	err = setattr_prepare(dentry, ia);
	if (err)
		goto out_err;

	stbfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_inode = stbfs_lower_inode(inode);

	/* prepare our own lower struct iattr (with the lower file) */
	memcpy(&lower_ia, ia, sizeof(lower_ia));
	if (ia->ia_valid & ATTR_FILE)
		lower_ia.ia_file = stbfs_lower_file(ia->ia_file);

	/*
	 * If shrinking, first truncate upper level to cancel writing dirty
	 * pages beyond the new eof; and also if its' maxbytes is more
	 * limiting (fail with -EFBIG before making any change to the lower
	 * level).  There is no need to vmtruncate the upper level
	 * afterwards in the other cases: we fsstack_copy_inode_size from
	 * the lower level.
	 */
	if (ia->ia_valid & ATTR_SIZE) {
		err = inode_newsize_ok(inode, ia->ia_size);
		if (err)
			goto out;
		truncate_setsize(inode, ia->ia_size);
	}

	/*
	 * mode change is for clearing setuid/setgid bits. Allow lower fs
	 * to interpret this in its own way.
	 */
	if (lower_ia.ia_valid & (ATTR_KILL_SUID | ATTR_KILL_SGID))
		lower_ia.ia_valid &= ~ATTR_MODE;

	/* notify the (possibly copied-up) lower inode */
	/*
	 * Note: we use d_inode(lower_dentry), because lower_inode may be
	 * unlinked (no inode->i_sb and i_ino==0.  This happens if someone
	 * tries to open(), unlink(), then ftruncate() a file.
	 */
	inode_lock(d_inode(lower_dentry));
	err = notify_change(lower_dentry, &lower_ia, /* note: lower_ia */
			    NULL);
	inode_unlock(d_inode(lower_dentry));
	if (err)
		goto out;

	/* get attributes from the lower inode */
	fsstack_copy_attr_all(inode, lower_inode);
	/*
	 * Not running fsstack_copy_inode_size(inode, lower_inode), because
	 * VFS should update our inode size, and notify_change on
	 * lower_inode should update its size.
	 */

out:
	stbfs_put_lower_path(dentry, &lower_path);
out_err:
	return err;
}

static int stbfs_getattr(const struct path *path, struct kstat *stat, 
                          u32 request_mask, unsigned int flags)
{
	int err;
        struct dentry *dentry = path->dentry;
	struct kstat lower_stat;
	struct path lower_path;

	stbfs_get_lower_path(dentry, &lower_path);
	err = vfs_getattr(&lower_path, &lower_stat, request_mask, flags);
	if (err)
		goto out;
	fsstack_copy_attr_all(d_inode(dentry),
			      d_inode(lower_path.dentry));
	generic_fillattr(d_inode(dentry), stat);
	stat->blocks = lower_stat.blocks;
out:
	stbfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int
stbfs_setxattr(struct dentry *dentry, struct inode *inode, const char *name,
		const void *value, size_t size, int flags)
{
	int err; struct dentry *lower_dentry;
	struct path lower_path;

	stbfs_get_lower_path(dentry, &lower_path);

	pr_info("Entered inside stxattr");
	err = is_cmd_allowed (dentry);
	if (err < 0)
		goto out;

	lower_dentry = lower_path.dentry;
	if (!(d_inode(lower_dentry)->i_opflags & IOP_XATTR)) {
		err = -EOPNOTSUPP;
		goto out;
	}
	pr_info("Setxattr dentry name is %s", dentry->d_iname);
	err = vfs_setxattr(lower_dentry, name, value, size, flags);
	if (err)
		goto out;
	fsstack_copy_attr_all(d_inode(dentry),
			      d_inode(lower_path.dentry));
out:
	stbfs_put_lower_path(dentry, &lower_path);
	return err;
}

static ssize_t
stbfs_getxattr(struct dentry *dentry, struct inode *inode,
		const char *name, void *buffer, size_t size)
{
	int err;
	struct dentry *lower_dentry;
	struct inode *lower_inode;
	struct path lower_path;

	stbfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_inode = stbfs_lower_inode(inode);
	if (!(d_inode(lower_dentry)->i_opflags & IOP_XATTR)) {
		err = -EOPNOTSUPP;
		goto out;
	}
	err = vfs_getxattr(lower_dentry, name, buffer, size);
	if (err)
		goto out;
	fsstack_copy_attr_atime(d_inode(dentry),
				d_inode(lower_path.dentry));
out:
	stbfs_put_lower_path(dentry, &lower_path);
	return err;
}

static ssize_t
stbfs_listxattr(struct dentry *dentry, char *buffer, size_t buffer_size)
{
	int err;
	struct dentry *lower_dentry;
	struct path lower_path;

	stbfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	if (!(d_inode(lower_dentry)->i_opflags & IOP_XATTR)) {
		err = -EOPNOTSUPP;
		goto out;
	}
	err = vfs_listxattr(lower_dentry, buffer, buffer_size);
	if (err)
		goto out;
	fsstack_copy_attr_atime(d_inode(dentry),
				d_inode(lower_path.dentry));
out:
	stbfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int
stbfs_removexattr(struct dentry *dentry, struct inode *inode, const char *name)
{
	int err;
	struct dentry *lower_dentry;
	struct inode *lower_inode;
	struct path lower_path;

	stbfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_inode = stbfs_lower_inode(inode);
	if (!(lower_inode->i_opflags & IOP_XATTR)) {
		err = -EOPNOTSUPP;
		goto out;
	}
	err = vfs_removexattr(lower_dentry, name);
	if (err)
		goto out;
	fsstack_copy_attr_all(d_inode(dentry), lower_inode);
out:
	stbfs_put_lower_path(dentry, &lower_path);
	return err;
}

const struct inode_operations stbfs_symlink_iops = {
	.permission	= stbfs_permission,
	.setattr	= stbfs_setattr,
	.getattr	= stbfs_getattr,
	.get_link	= stbfs_get_link,
	.listxattr	= stbfs_listxattr,
};

const struct inode_operations stbfs_dir_iops = {
	.create		= stbfs_create,
	.lookup		= stbfs_lookup,
	.link		= stbfs_link,
	.unlink		= stbfs_unlink,
	.symlink	= stbfs_symlink,
	.mkdir		= stbfs_mkdir,
	.rmdir		= stbfs_rmdir,
	.mknod		= stbfs_mknod,
	.rename		= stbfs_rename,
	.permission	= stbfs_permission,
	.setattr	= stbfs_setattr,
	.getattr	= stbfs_getattr,
	.listxattr	= stbfs_listxattr,
};

const struct inode_operations stbfs_main_iops = {
	.permission	= stbfs_permission,
	.setattr	= stbfs_setattr,
	.getattr	= stbfs_getattr,
	.listxattr	= stbfs_listxattr,
};

static int stbfs_xattr_get(const struct xattr_handler *handler,
			    struct dentry *dentry, struct inode *inode,
			    const char *name, void *buffer, size_t size)
{
	return stbfs_getxattr(dentry, inode, name, buffer, size);
}

static int stbfs_xattr_set(const struct xattr_handler *handler,
			    struct dentry *dentry, struct inode *inode,
			    const char *name, const void *value, size_t size,
			    int flags)
{
	if (value)
		return stbfs_setxattr(dentry, inode, name, value, size, flags);

	BUG_ON(flags != XATTR_REPLACE);
	return stbfs_removexattr(dentry, inode, name);
}

const struct xattr_handler stbfs_xattr_handler = {
	.prefix = "",		/* match anything */
	.get = stbfs_xattr_get,
	.set = stbfs_xattr_set,
};

const struct xattr_handler *stbfs_xattr_handlers[] = {
	&stbfs_xattr_handler,
	NULL
};
