/*
 *  setkey.c
 *  
 *
 *  Created by Junxing Yang on 3/25/12.
 *  Copyright (c) 2012 Stony Brook University. All rights reserved.
 */

/* code comes from my HW1 and kernel_user_space_howto(http://people.ee.ethz.ch/~arkeller/linux/multi/kernel_user_space_howto-4.html)
 */
 
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <openssl/evp.h>

#define MY_MACIG 'G'
#define RESET_IOCTL _IOW(MY_MACIG, 0, int)
#define WRITE_IOCTL _IOW(MY_MACIG, 1, int)

#define AES_KEYLEN 32
/* salt comes from CEPH_AES_IV */
const char *salt = "cephsageyudagreg";

void disp_usage()
{   
    puts("usage:");
    puts("\t setkey [-m mountpoint] [-k key] "); 
    puts("input [-k 0000] to reset the key.");
    puts("example:");
    puts("\t setkey -m /mnt/wrapfs -k mypassword");
}

/* filter_copy removes the '\n' from the key */
void filter_copy(char **result, const char *src, char c)
{
    char *temp = (char *)malloc(strlen(src)+1);
    int i,j;  
    for (i = 0, j = 0; src[i] != '\0'; i++)  
    {  
	if (src[i] != c)  
	    temp[j++] = src[i];  
    }
    temp[j] = '\0';
    *result = (char *)malloc(strlen(temp)+1);
    strcpy(*result, temp);
    free(temp);
}

int main(int argc, char *argv[])
{
    char *userkey = NULL;
    int opt = 0;
    const char *optstring = "m:k:h";
    char key[AES_KEYLEN];
    
    int fd = -1;
    
    if (argc < 3) {
	puts("wrong argument(s):too few arguments");
	disp_usage();
	return -1;
    }
    while ((opt = getopt(argc, argv, optstring)) != -1)
    {
	switch (opt) {
	    case 'k':
		/* remove the '\n' from password */
		filter_copy(&userkey, optarg, '\n');
		break;
	    case 'm':
		if ((fd = open(optarg, O_RDONLY)) < 0) {
		    perror("open");
		    return -1;
		}
		break;
	    case 'h':
	    case '?':
		disp_usage();
		return 0;
	    default:
                /* You won't actually get here. */
		break;
	}
    }
    
    if (userkey == NULL) {
	puts("wrong argument(s): null key");
	disp_usage();
	return -1;
    }else if (strcmp(userkey,"0000") == 0)
    {
	/* input 0000 as key to reset the key using RESET_IOCTL*/
	puts("reset key");
	if(ioctl(fd, RESET_IOCTL, 0) < 0)
	    perror("setkey");
	return 0;
    }
    
    /* use openssl to hash the key */
    if(PKCS5_PBKDF2_HMAC_SHA1((void *)userkey, strlen(userkey), 
                              (void *)salt, strlen(salt), 10000,
                              AES_KEYLEN, (void *)key) != 1)
    {
	puts("failed to generate key.");
	return -1;
    }
    
    /* set the key via WRITE_IOCTL */
    if(ioctl(fd, WRITE_IOCTL, key) < 0)
	perror("setkey");
    
    return 0;
    
}
