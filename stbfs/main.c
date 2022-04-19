// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 1998-2020 Erez Zadok
 * Copyright (c) 2009	   Shrikar Archak
 * Copyright (c) 2003-2020 Stony Brook University
 * Copyright (c) 2003-2020 The Research Foundation of SUNY
 */

#include "stbfs.h"
#include <linux/module.h>
#include <linux/parser.h>
#include <linux/string.h>
#include <linux/crypto.h>
#include <crypto/hash.h>
#include <linux/slab.h>

#define SHA256_LEN 32

enum {stbfs_opt_enckey, stbfs_opt_err};

static const match_table_t tokens = {
	{stbfs_opt_enckey, "enc=%s"},
	{stbfs_opt_err, NULL}
};

void *hash_cipher_key = NULL;
/*
 * There is no need to lock the stbfs_super_info's rwsem as there is no
 * way anyone can have a reference to the superblock at this point in time.
 */
static int stbfs_read_super(struct super_block *sb, void *raw_data, int silent)
{
	int err = 0;
	struct super_block *lower_sb;
	struct path lower_path;
	char *dev_name = (char *) raw_data;
	struct inode *inode;

	if (!dev_name) {
		printk(KERN_ERR
		       "stbfs: read_super: missing dev_name argument\n");
		err = -EINVAL;
		goto out;
	}

	/* parse lower path */
	err = kern_path(dev_name, LOOKUP_FOLLOW | LOOKUP_DIRECTORY,
			&lower_path);
	if (err) {
		printk(KERN_ERR	"stbfs: error accessing "
		       "lower directory '%s'\n", dev_name);
		goto out;
	}

	/* allocate superblock private data */
	sb->s_fs_info = kzalloc(sizeof(struct stbfs_sb_info), GFP_KERNEL);
	if (!STBFS_SB(sb)) {
		printk(KERN_CRIT "stbfs: read_super: out of memory\n");
		err = -ENOMEM;
		goto out_free;
	}


	/* set the lower superblock field of upper superblock */
	lower_sb = lower_path.dentry->d_sb;
	atomic_inc(&lower_sb->s_active);
	stbfs_set_lower_super(sb, lower_sb);

	/* inherit maxbytes from lower file system */
	sb->s_maxbytes = lower_sb->s_maxbytes;

	/*
	 * Our c/m/atime granularity is 1 ns because we may stack on file
	 * systems whose granularity is as good.
	 */
	sb->s_time_gran = 1;

	sb->s_op = &stbfs_sops;
	sb->s_xattr = stbfs_xattr_handlers;

	sb->s_export_op = &stbfs_export_ops; /* adding NFS support */

	/* get a new inode and allocate our root dentry */
	inode = stbfs_iget(sb, d_inode(lower_path.dentry));
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto out_sput;
	}
	sb->s_root = d_make_root(inode);
	if (!sb->s_root) {
		err = -ENOMEM;
		goto out_iput;
	}
	d_set_d_op(sb->s_root, &stbfs_dops);

	/* link the upper and lower dentries */
	sb->s_root->d_fsdata = NULL;
	err = new_dentry_private_data(sb->s_root);
	if (err)
		goto out_freeroot;

	/* if get here: cannot have error */

	/* set the lower dentries for s_root */
	stbfs_set_lower_path(sb->s_root, &lower_path);

	/*
	 * No need to call interpose because we already have a positive
	 * dentry, which was instantiated by d_make_root.  Just need to
	 * d_rehash it.
	 */
	d_rehash(sb->s_root);
	((struct stbfs_sb_info *)(sb->s_fs_info))->enckey = NULL;
	if (hash_cipher_key != NULL)
	{
		((struct stbfs_sb_info *)(sb->s_fs_info))->enckey = kmalloc(SHA256_LEN, GFP_KERNEL);
		if (((struct stbfs_sb_info *)(sb->s_fs_info))->enckey == NULL)
		{
			err = -ENOMEM;
			goto out;
		}
		memcpy(((struct stbfs_sb_info *)(sb->s_fs_info))->enckey, hash_cipher_key, SHA256_LEN);
		pr_info("Super block private data hash key is %s", (char *)((struct stbfs_sb_info *)(sb->s_fs_info))->enckey);
	}
	((struct stbfs_sb_info *)(sb->s_fs_info))->mount_point = NULL;
	((struct stbfs_sb_info *)(sb->s_fs_info))->mount_point = kmalloc(strlen(dev_name) + 1, GFP_KERNEL);
	if (((struct stbfs_sb_info *)(sb->s_fs_info))->mount_point == NULL)
	{
		err = -ENOMEM;
		goto out;
	}
	memset(((struct stbfs_sb_info *)(sb->s_fs_info))->mount_point, '\0', strlen(dev_name) + 1);
	memcpy(((struct stbfs_sb_info *)(sb->s_fs_info))->mount_point, dev_name, strlen(dev_name));
	pr_info("Mount point is %s", ((struct stbfs_sb_info *)(sb->s_fs_info))->mount_point);

	if (!silent)
		printk(KERN_INFO
		       "stbfs: mounted on top of %s type %s\n",
		       dev_name, lower_sb->s_type->name);
	goto out; /* all is well */

	/* no longer needed: free_dentry_private_data(sb->s_root); */
out_freeroot:
	dput(sb->s_root);
out_iput:
	iput(inode);
out_sput:
	/* drop refs we took earlier */
	atomic_dec(&lower_sb->s_active);
	kfree(STBFS_SB(sb));
	sb->s_fs_info = NULL;
out_free:
	path_put(&lower_path);
out:
	if (hash_cipher_key != NULL)
	{
		pr_info("Cleanup: Freeing memory for hash key");
		kfree(hash_cipher_key);
	}
	return err;
}

int generate_hash(const u8 *input, unsigned int hash_length, u8 *output)
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
Parsing the options of mount
*/
static int stbfs_parse_options (char *options)
{
	int ret = 0;
	char *p = NULL;
	int token;
	substring_t args[MAX_OPT_ARGS];

	if ((!options) || strlen(options) == 0)
	{
		pr_info("No options specified");
		goto out;
	}

	hash_cipher_key = kmalloc(SHA256_LEN, GFP_KERNEL);
	if (hash_cipher_key == NULL) {
		ret = -ENOMEM;
		goto out;
	}
	memset(hash_cipher_key, 0, SHA256_LEN);

	while ((p = strsep(&options, ",")) != NULL)
	{
		if (!*p)
			continue;
		
		token = match_token(p, tokens, args);
		switch (token)
		{
			case stbfs_opt_enckey:
				if (strlen(args[0].from) < 6)
				{
					ret = -EINVAL;
					pr_alert("Encryption password contains less than 6 characters");
					goto out;
				}
				//strcpy(hash_cipher_key, args[0].from);
				//pr_info("Hash cipher key is %s",(char *)hash_cipher_key);
				ret = generate_hash((const u8 *)args[0].from, strlen(args[0].from), (u8 *)hash_cipher_key);
				if (ret < 0)
				 	goto out;
				break;

			default:
				pr_info("Error received\n");
		}
	}

out:
	return ret;
}

struct dentry *stbfs_mount(struct file_system_type *fs_type, int flags,
			    const char *dev_name, void *raw_data)
{
	int err = 0;
	void *lower_path_name = (void *) dev_name;
	err = stbfs_parse_options(raw_data);

	if (err < 0)
	{
		return ERR_PTR(err);
	}
	return mount_nodev(fs_type, flags, lower_path_name,
			   stbfs_read_super);
}

static struct file_system_type stbfs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= STBFS_NAME,
	.mount		= stbfs_mount,
	.kill_sb	= generic_shutdown_super,
	.fs_flags	= 0,
};
MODULE_ALIAS_FS(STBFS_NAME);

static int __init init_stbfs_fs(void)
{
	int err;

	pr_info("Registering stbfs " STBFS_VERSION "\n");

	err = stbfs_init_inode_cache();
	if (err)
		goto out;
	err = stbfs_init_dentry_cache();
	if (err)
		goto out;
	err = register_filesystem(&stbfs_fs_type);
out:
	if (err) {
		stbfs_destroy_inode_cache();
		stbfs_destroy_dentry_cache();
	}
	return err;
}

static void __exit exit_stbfs_fs(void)
{
	stbfs_destroy_inode_cache();
	stbfs_destroy_dentry_cache();
	unregister_filesystem(&stbfs_fs_type);
	pr_info("Completed stbfs module unload\n");
}

MODULE_AUTHOR("Erez Zadok, Filesystems and Storage Lab, Stony Brook University"
	      " (http://www.fsl.cs.sunysb.edu/)");
MODULE_DESCRIPTION("Stbfs " STBFS_VERSION
		   " (http://stbfs.filesystems.org/)");
MODULE_LICENSE("GPL");

module_init(init_stbfs_fs);
module_exit(exit_stbfs_fs);
