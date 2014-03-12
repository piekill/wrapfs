/*
 * Copyright (c) 1998-2011 Erez Zadok
 * Copyright (c) 2009	   Shrikar Archak
 * Copyright (c) 2003-2011 Stony Brook University
 * Copyright (c) 2003-2011 The Research Foundation of SUNY
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "wrapfs.h"
#include <linux/gfp.h>

static int wrapfs_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	int err;
	struct file *file, *lower_file;
	const struct vm_operations_struct *lower_vm_ops;
	struct vm_area_struct lower_vma;

	memcpy(&lower_vma, vma, sizeof(struct vm_area_struct));
	file = lower_vma.vm_file;
	lower_vm_ops = WRAPFS_F(file)->lower_vm_ops;
	BUG_ON(!lower_vm_ops);

	lower_file = wrapfs_lower_file(file);
	/*
	 * XXX: vm_ops->fault may be called in parallel.  Because we have to
	 * resort to temporarily changing the vma->vm_file to point to the
	 * lower file, a concurrent invocation of wrapfs_fault could see a
	 * different value.  In this workaround, we keep a different copy of
	 * the vma structure in our stack, so we never expose a different
	 * value of the vma->vm_file called to us, even temporarily.  A
	 * better fix would be to change the calling semantics of ->fault to
	 * take an explicit file pointer.
	 */
	lower_vma.vm_file = lower_file;
	err = lower_vm_ops->fault(&lower_vma, vmf);
	
	return err;
}

/* code is a modification of old unionfs/mmap.c */
static int wrapfs_writepage(struct page *page, struct writeback_control *wbc)
{
    int err = -EIO;
    struct inode *inode;
    struct inode *lower_inode;
    struct page *lower_page;
    
#ifdef WRAPFS_CRYPTO
    void *cipher, *plain;
#endif

    struct address_space *lower_mapping; /* lower inode mapping */
    gfp_t mask;
    
    BUG_ON(!PageUptodate(page));
    inode = page->mapping->host;
    /* if no lower inode, nothing to do */
    if (!inode || !WRAPFS_I(inode) || WRAPFS_I(inode)->lower_inode) {
	err = 0;
	goto out;
    }
    lower_inode = wrapfs_lower_inode(inode);
    lower_mapping = lower_inode->i_mapping;
    
    /*
     * find lower page (returns a locked page)
     *
     * We turn off __GFP_FS while we look for or create a new lower
     * page.  This prevents a recursion into the file system code, which
     * under memory pressure conditions could lead to a deadlock.  This
     * is similar to how the loop driver behaves (see loop_set_fd in
     * drivers/block/loop.c).  If we can't find the lower page, we
     * redirty our page and return "success" so that the VM will call us
     * again in the (hopefully near) future.
     */
    mask = mapping_gfp_mask(lower_mapping) & ~(__GFP_FS);
    lower_page = find_or_create_page(lower_mapping, page->index, mask);
    if (!lower_page) {
	err = 0;
	set_page_dirty(page);
	goto out;
    }
#ifdef WRAPFS_CRYPTO
    plain = kmap(page);
    cipher = kmap(lower_page);
    if (MMAP_FLAG == 0){
	err = -EPERM;
	goto out_release;
    }
    /* this piece of code maps page and lower_page
       then do the encryption
     */
    err = wrapfs_encrypt(WRAPFS_SB(inode->i_sb)->key,cipher, plain, PAGE_CACHE_SIZE);
    if (err < 0) {
	goto out_release;
    }
#else
    /* copy page data from our upper page to the lower page */
    copy_highpage(lower_page, page); 
#endif
    
    flush_dcache_page(lower_page);
    SetPageUptodate(lower_page);
    set_page_dirty(lower_page);
    
    /*
     * Call lower writepage (expects locked page).  However, if we are
     * called with wbc->for_reclaim, then the VFS/VM just wants to
     * reclaim our page.  Therefore, we don't need to call the lower
     * ->writepage: just copy our data to the lower page (already done
     * above), then mark the lower page dirty and unlock it, and return
     * success.
     */
    if (wbc->for_reclaim) {
	unlock_page(lower_page);
	goto out_release;
    }
    
    BUG_ON(!lower_mapping->a_ops->writepage);
    wait_on_page_writeback(lower_page); /* prevent multiple writers */
    clear_page_dirty_for_io(lower_page); /* emulate VFS behavior */
    err = lower_mapping->a_ops->writepage(lower_page, wbc);
    if (err < 0)
	goto out_release;
    
    /*
     * Lower file systems such as ramfs and tmpfs, may return
     * AOP_WRITEPAGE_ACTIVATE so that the VM won't try to (pointlessly)
     * write the page again for a while.  But those lower file systems
     * also set the page dirty bit back again.  Since we successfully
     * copied our page data to the lower page, then the VM will come
     * back to the lower page (directly) and try to flush it.  So we can
     * save the VM the hassle of coming back to our page and trying to
     * flush too.  Therefore, we don't re-dirty our own page, and we
     * never return AOP_WRITEPAGE_ACTIVATE back to the VM (we consider
     * this a success).
     *
     * We also unlock the lower page if the lower ->writepage returned
     * AOP_WRITEPAGE_ACTIVATE.  (This "anomalous" behaviour may be
     * addressed in future shmem/VM code.)
     */
    if (err == AOP_WRITEPAGE_ACTIVATE) {
	err = 0;
	unlock_page(lower_page);
    }
    
    /* all is well */
    
    /* lower mtimes have changed: update ours */
    wrapfs_copy_attr_times(inode);
    
out_release:
#ifdef WRAPFS_CRYPTO
    kunmap(page);
    kunmap(lower_page);
#endif
    /* b/c find_or_create_page increased refcnt */
    page_cache_release(lower_page);
out:
    /*
     * We unlock our page unconditionally, because we never return
     * AOP_WRITEPAGE_ACTIVATE.
     */
    unlock_page(page);
    return err;
}

/* code is a modification of old unionfs/mmap.c */
/* Readpage expects a locked page, and must unlock it */
static int wrapfs_readpage(struct file *file, struct page *page)
{
    int err = 0;
    int count = 0;
    struct file *lower_file;
    struct inode *inode;
    mm_segment_t old_fs;
    char *page_data = NULL;
    mode_t orig_mode;
    
#ifdef WRAPFS_CRYPTO         
    /* for decryption, use a temp page(cipher_page) to store what we
       vfs_read from lower_file, then decrypt it and store the result
       in upper page
     */
    struct page *cipher_page;
    void *cipher;
    if (MMAP_FLAG == 0) {
	err = -EPERM;
	goto out_page;
    }
    /* init temp page here */
    cipher_page = alloc_page(GFP_KERNEL);
    if (IS_ERR(cipher_page)){
	err = PTR_ERR(cipher_page);
	goto out_page;
    }
    cipher = kmap(cipher_page);

#endif
    if (!WRAPFS_F(file)) {
	err = -ENOENT;
	goto out;
    }
    lower_file = wrapfs_lower_file(file);
    /* FIXME: is this assertion right here? */
    BUG_ON(lower_file == NULL);
    
    inode = file->f_path.dentry->d_inode;
    
    page_data = (char *) kmap(page);
    /*
     * Use vfs_read because some lower file systems don't have a
     * readpage method, and some file systems (esp. distributed ones)
     * don't like their pages to be accessed directly.  Using vfs_read
     * may be a little slower, but a lot safer, as the VFS does a lot of
     * the necessary magic for us.
     */
    lower_file->f_pos = page_offset(page);
    old_fs = get_fs();
    set_fs(KERNEL_DS);
    /*
     * generic_file_splice_write may call us on a file not opened for
     * reading, so temporarily allow reading.
     */
    orig_mode = lower_file->f_mode;
    lower_file->f_mode |= FMODE_READ;
#ifdef WRAPFS_CRYPTO
    count = vfs_read(lower_file, cipher, PAGE_CACHE_SIZE,
		   &lower_file->f_pos);
#else
    count = vfs_read(lower_file, page_data, PAGE_CACHE_SIZE,
		     &lower_file->f_pos);
#endif
    lower_file->f_mode = orig_mode;
    
    set_fs(old_fs);
#ifdef WRAPFS_CRYPTO
    /* do decryption here */
    if (count >= 0) 
	err = wrapfs_decrypt(WRAPFS_SB(inode->i_sb)->key,page_data, cipher, count);
    if (err < 0)
	goto out;
#endif
    if (count >= 0 && count < PAGE_CACHE_SIZE)
	memset(page_data + count, 0, PAGE_CACHE_SIZE - count);
    
    /* if vfs_read succeeded above, sync up our times */
    wrapfs_copy_attr_times(inode);
    kunmap(page);
    flush_dcache_page(page);
    /*
     * we have to unlock our page, b/c we _might_ have gotten a locked
     * page.  but we no longer have to wakeup on our page here, b/c
     * UnlockPage does it
     */
out:
#ifdef WRAPFS_CRYPTO
    kunmap(cipher_page);
    __free_page(cipher_page);
out_page:
#endif
    if (err == 0)
	SetPageUptodate(page);
    else
	ClearPageUptodate(page);
    
    unlock_page(page);    
    return err;
}

/* code comes from ecryptfs/mmap.c and old unionfs/mmap.c 
   suggestion comes from ces506 mailing list
 */
static int wrapfs_write_begin(struct file *file,
                        struct address_space *mapping,
                        loff_t pos, unsigned len, unsigned flags,
                        struct page **pagep, void **fsdata)
{
    pgoff_t index = pos >> PAGE_CACHE_SHIFT;
    struct page *page;
    page = grab_cache_page_write_begin(mapping, index, flags);
    if (!page)
	    return -ENOMEM;
    *pagep = page;
    wrapfs_copy_attr_times(file->f_path.dentry->d_inode);
    return 0;
}

/* code is a modification of old unionfs/mmap.c */
static int wrapfs_write_end(struct file *file,
                        struct address_space *mapping,
                        loff_t pos, unsigned len, unsigned copied,
                        struct page *page, void *fsdata)
{
    int err = -ENOMEM;
    struct inode *inode, *lower_inode;
    struct file *lower_file = NULL;
    unsigned from = pos & (PAGE_CACHE_SIZE - 1);
    unsigned bytes = copied;
    char *page_data = NULL;
    mm_segment_t old_fs;
    
#ifdef WRAPFS_CRYPTO 
    struct page *cipher_page;
    void *cipher;
#endif
    
    BUG_ON(file == NULL);
    
    inode = page->mapping->host;
    
    if (WRAPFS_F(file) != NULL)
	lower_file = wrapfs_lower_file(file);
    
    /* FIXME: is this assertion right here? */
    BUG_ON(lower_file == NULL);
    
    page_data = (char *)kmap(page);
#ifdef WRAPFS_CRYPTO
    /*  for encryption, use a temp page(cipher_page) to store the result
     	of encryption of upper page, then use vfs_write to write this page
     	into lower file
     */ 
    if (MMAP_FLAG == 0) {
	err = -EPERM;
	goto out_page;
    }
    /* init temp page */
    cipher_page = alloc_page(GFP_KERNEL);
    if (IS_ERR(cipher_page)){
	err = PTR_ERR(cipher_page);
	goto out_page;
    }
    cipher = kmap(cipher_page);
    
    /* do encryption */
    err = wrapfs_encrypt(WRAPFS_SB(inode->i_sb)->key,cipher, page_data, bytes);
    if (err < 0)
	goto out;
#endif
    lower_file->f_pos = page_offset(page) + from;
    /*
     * We use vfs_write instead of copying page data and the
     * prepare_write/commit_write combo because file system's like
     * GFS/OCFS2 don't like things touching those directly,
     * calling the underlying write op, while a little bit slower, will
     * call all the FS specific code as well
     */
    old_fs = get_fs();
    set_fs(KERNEL_DS);
#ifdef WRAPFS_CRYPTO
    /* write the result to lower file */
    err = vfs_write(lower_file, cipher + from, bytes,
		    &lower_file->f_pos);
#else
    err = vfs_write(lower_file, page_data + from, bytes,
		    &lower_file->f_pos);
#endif
    set_fs(old_fs);
    
    kunmap(page);
    
    if (err < 0)
	goto out;
    
    /* if vfs_write succeeded above, sync up our times/sizes */
    lower_inode = lower_file->f_path.dentry->d_inode;
    if (!lower_inode)
	lower_inode = wrapfs_lower_inode(inode);
    BUG_ON(!lower_inode);
    fsstack_copy_inode_size(inode, lower_inode);
    wrapfs_copy_attr_times(inode);
    mark_inode_dirty_sync(inode);
    
out:
#ifdef WRAPFS_CRYPTO
    kunmap(cipher_page);
    __free_page(cipher_page);
out_page:
#endif
    if (err < 0)
	ClearPageUptodate(page);
    unlock_page(page);
    return err;		/* assume all is ok */
}

/* code comes from old unionfs/mmap.c */
/*
 * Although wrapfs isn't a block-based file system, it may stack on one.
 * ->bmap is needed, for example, to swapon(2) files.
 */
sector_t wrapfs_bmap(struct address_space *mapping, sector_t block)
{
    int err = -EINVAL;
    struct inode *inode, *lower_inode;
    sector_t (*bmap)(struct address_space *, sector_t);
    
    inode = (struct inode *)mapping->host;
    lower_inode = wrapfs_lower_inode(inode);
    if (!lower_inode)
	goto out;
    bmap = lower_inode->i_mapping->a_ops->bmap;
    if (bmap)
	err = bmap(lower_inode->i_mapping, block);
out:
    return err;
}

/* address space operations */
const struct address_space_operations wrapfs_aops = {
    .writepage	= wrapfs_writepage,
    .readpage	= wrapfs_readpage,
    .write_begin= wrapfs_write_begin,
    .write_end  = wrapfs_write_end,
    .bmap	= wrapfs_bmap,
};

/*
 * XXX: the default address_space_ops for wrapfs is empty.  We cannot set
 * our inode->i_mapping->a_ops to NULL because too many code paths expect
 * the a_ops vector to be non-NULL.
 */
/*const struct address_space_operations wrapfs_aops = {
	 empty on purpose 
};*/

const struct vm_operations_struct wrapfs_vm_ops = {
	.fault		= wrapfs_fault,
};
