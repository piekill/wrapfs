/*
 *  crypto.c
 *  
 *
 *  Created by Junxing Yang on 3/24/12.
 *  Copyright (c) 2012 Stony Brook University. All rights reserved.
 */

#include "wrapfs.h"
#include <linux/scatterlist.h>

/* IV value comes from /linux/ceph/ceph_fs.h */
#define CEPH_AES_IV "cephsageyudagreg"

struct blkcipher_desc *desc = NULL;

/* initialize blkcipher_desc *desc using void *key 
   code comes from my HW1.
   important note: use CTR mode to avoid padding.
 */
int init_cipher(void *key)
{
    struct crypto_blkcipher *tfm = NULL;
    int err = 0;
    if (key == NULL) 
	goto out;
    
    desc = kzalloc(sizeof(struct blkcipher_desc), GFP_KERNEL);
    if (desc == NULL) {
	err = -ENOMEM;
	goto out;
    }
    
    tfm = crypto_alloc_blkcipher("ctr(aes)", 0, CRYPTO_ALG_ASYNC);
    
    if (IS_ERR(tfm)) {
	err = PTR_ERR(tfm);
	goto out_desc;
    }
    
    desc->tfm = tfm;
    desc->flags = 0;
    
    err = crypto_blkcipher_setkey((void *)tfm, key, AES_KEYLEN);
    if (err != 0)
	goto out_tfm;

    goto out;
out_tfm:
    kfree(tfm);
out_desc:
    kfree(desc);
out:
    return err;
}

/* ctr mode required to re-initialize crypto_blkcipher *tfm 
   before encryption and decryption
 */
static inline int reinit_cipher(void *key)
{
    int err = 0;
    if (key == NULL || desc == NULL)
	goto out;

    if (desc->tfm != NULL)
	kfree(desc->tfm);
    
    desc->tfm = crypto_alloc_blkcipher("ctr(aes)", 0, CRYPTO_ALG_ASYNC);
    if (IS_ERR(desc->tfm)) {
	err = PTR_ERR(desc->tfm);
	goto out;
    }
    err = crypto_blkcipher_setkey((void *)desc->tfm, key, AES_KEYLEN);
    
    /*memcpy(crypto_blkcipher_crt(desc->tfm)->iv, CEPH_AES_IV,
     crypto_blkcipher_ivsize(desc->tfm));*/

out:
    return err;
}

/* encryption. code comes from my HW1(basically /net/ceph/crypto.c)*/
int wrapfs_encrypt(void *key, void *dst, const void *src, size_t len)
{
    struct scatterlist sg_in[1], sg_out[1];
    int ret = 0;
    if (desc == NULL) {
	memcpy(dst, src, len);
	goto out;
    }
    
    ret = reinit_cipher(key);
    if (ret < 0) 
	goto out;
	
    sg_init_table(sg_in, 1);
    sg_set_buf(&sg_in[0], src, len);
    sg_init_table(sg_out, 1);
    sg_set_buf(sg_out, dst, len);
    
    ret = crypto_blkcipher_encrypt(desc, sg_out,
				    sg_in, len);
    if (ret < 0)
	pr_err("wrapfs: encrypt failed %d\n", ret);
    
out:
    return ret;
}

/* code comes from my HW1(basically /net/ceph/crypto.c) */
int wrapfs_decrypt(void *key, void *dst, const void *src, size_t len)
{
    struct scatterlist sg_in[1], sg_out[1];
    int ret = 0;
    
    if (desc == NULL) {
	memcpy(dst, src, len);
	goto out;
    }
    ret = reinit_cipher(key);
    if (ret < 0) 
	goto out;

    sg_init_table(sg_in, 1);
    sg_init_table(sg_out, 1);
    sg_set_buf(sg_in, src, len);
    sg_set_buf(&sg_out[0], dst, len);
    
    ret = crypto_blkcipher_decrypt(desc, sg_out, sg_in, len);

    if (ret < 0)
	pr_err("wrapfs: decrypt failed %d\n", ret);
	
out:
    return ret;
}
