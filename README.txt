				CSE 506 HW2
			        Junxing Yang
				ID:108312768
				March 25, 2012.
Overview
--------
Task 1 and 2 are implemented.

Files submitted
---------------
1) modified:
	file.c
	main.c
	Makefile
	mmap.c
	wrapfs.h
2) new:
	crypto.c
	README.HW2
	util/setkey.c
	util/Makefile

Task 1:
-------
1) modify main.c
	- make changes in main.c so wrapfs accepts a new option "-o mmap". 
	- Use a global variable MMAP_FLAG to represent this option. 
	- Use address space operations when MMAP_FLAG == 1.

2) modify file.c:
	- if MMAP_FLAG == 1, use do_sync_read() and do_sync_write() in
	  wrapfs_read() and wrapfs_write(), which will invoke address space 
	  ops.
	- if MMAP_FLAG == 1, use generic_file_mmap() in wrapfs_mmap()
	   (code from old unionfs/file.c)

3) modify mmap.c:
	- add wrapfs_writepage() (base on unionfs/mmap.c->unionfs_writepage())
	- add wrapfs_readdpage() (base on unionfs/mmap.c->unionfs_readpage())
	- add wrapfs_write_begin() 
	  (base on ecryptfs/mmap.c->ecryptfs_write_begin())
	- add wrapfs_write_end() 
	  (base on unionfs/mmap.c->unionfs_commit_write())
	- add wrapfs_bmap() (base on unionfs/mmap.c->unionfs_bmap())
	- add those functions to address_space_operations wrapfs_aops

4)modify wrapfs.h
	- add declarations and a helper routine wrapfs_copy_attr_times()
	  to copy a/m/ctime from the lower branch with the newest times
	  (base on unionfs->unionfs_copy_attr_times())

Task 1 tests:
-------------
1)a typical testcase:
	IMPORTANT:
		Turn off the macro WRAPFS_CRYPTO which is by default defined in
		wrafps.h and recompile.
	$mount -t wraps /home/yang /mnt/wrapfs -o mmap
	$cd /mnt/wrapfs
	$ (do some file operation commands here)
2)LTP:
	-passed tests: fsx dio mm ipc sched math nptl pty containers
			fs(gf01-gf10) and major part of syscalls
	-failed tests: fs(gf10 after) -- out of memory(probably due to small memory)
			syscall(create) -- oops
Task 2:
-------
1)new file crypto.c:
	- global variable struct blkcipher_desc *desc
	- function init_cipher() to initialize this variable
	- wrapfs_encrypt() and wrapfs_decrypt() for encryption and decryption
	- those 3 functions are based on my HW1 (basically /net/ceph/crypto.c)
	- a helper function reinit_cipher() to reset cipher and key

2)modify wrapfs.h
	- define WRITE_IOCTL for ioctl to set key
	- define RESET_IOCTL for ioctl to reset key to 0
	- add char key[AES_KEYLEN] to struct wrapfs_sb_info to store a key

3)modify file.c
	- modify wrapfs_unlocked_ioctl() to support WRITE_IOCTL and RESET_IOCTL
	- ioctl code(including those in wrapfs)is based on
	  kernel_user_space_howto(http://people.ee.ethz.ch/~arkeller/linux/
	  multi/kernel_user_space_howto-4.html)

4)modify mmap.c
	- in wrapfs_writepage(): use kmap for lower_page and upper_page,
	  encrypt upper_page into lower_page. 
	- in wrapfs_readpage(): use a temp page(cipher_page) to store what we
	  vfs_read from lower_file, then decrypt it and store the result
	  in upper page
	- in wrapfs_write_end():use a temp page(cipher_page) to store the 
	  result of encryption of upper page, then use vfs_write to write this
	  page into lower file

5)new file util/setkey.c:
	- allow user to set a key via command $setkey [-m mountpoint] [-k key]
	- use openssl to hash the key (as in HW1)
	- if user specifies the key to be 0000, use RESET_IOCTL to reset the key to 0;
	- otherwise set the key using WRITE_IOCTL

Task 2 IMPORTANT decisions:
---------------------------
1)Use CTR mode for encryption and decryption so no padding is needed. It requires reset of cipher and key before every en/decryptions (this is what reinit_cipher() in crypto.c is for)

2)Allow user to set different keys multiply times in one mount. But user has to use the right key(the same key that is set when the file is encrypted) to read a file correctly. If not, he will get wrong data.

3)When key or cipher is not set, no en/decryption happens and wrapfs behaves the same as in task 1 (no need to report errors and stop running to force user to set a key)

Task 2 tests:
-------------
1) a typical testcase:
	- generate user program "setkey" using $cd ./util;make 
	- $mount -t wrapfs /home/yang /mnt/wrapfs -o mmap
	- $./setkey -m /mnt/wrapfs -k mypassword
	- $cd /mnt/wrapfs
	- $echo 1234 > test;cat test //you will see 1234
	- $cat /home/yang/test       //you will see a cipher text
   Note:
	if set a different key or reset the key using 0000 and $cat text, you may still
	see the plain text because the page is cached. But uncached file pages will use
	the new key for en/decryption.
	if umount and re-mount use a different key, you'll get wrong data.
2) LTP:
	- passed tests: part of syscalls, dio, mm, ipc, sched, 
			math(abs01 atof01 fptest01 fptest02),
			nptl, pty, containers
	- failed tests: fs(after gf10) -- out of memory(probably due to small memory)
			rest of math
			part of syscalls
			fsx
