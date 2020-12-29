#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>

#include <linux/kernel.h>	/* printk() */
#include <linux/slab.h>		/* kmalloc() */
#include <linux/fs.h>		/* everything... */
#include <linux/errno.h>	/* error codes */
#include <linux/types.h>	/* size_t */
#include <linux/proc_fs.h>
#include <linux/fcntl.h>	/* O_ACCMODE */
#include <linux/seq_file.h>
#include <linux/cdev.h>

#include <asm/switch_to.h>		/* cli(), *_flags */
#include <asm/uaccess.h>	/* copy_*_user */


#include <linux/version.h>  /* in order to check kernel version */


//  check if linux/uaccess.h is required for copy_*_user
//instead of asm/uaccess
//required after linux kernel 4.1+ ?
#ifndef __ASM_ASM_UACCESS_H
    #include <linux/uaccess.h>
#endif


#include "vault_ioctl.h"

#define VAULT_MAJOR 0
#define VAULT_NR_DEVS 4
#define VAULT_MAX_TEXT_SIZE 80

int vault_major = VAULT_MAJOR;
int vault_minor = 0;
int vault_nr_devs = VAULT_NR_DEVS;
int vault_max_text_size = VAULT_MAX_TEXT_SIZE;
static char * vault_default_key_text = "abcd";

module_param(vault_major, int, S_IRUGO);
module_param(vault_minor, int, S_IRUGO);
module_param(vault_nr_devs, int, S_IRUGO);


MODULE_AUTHOR("Alessandro Rubini, Jonathan Corbet, Ekin, Farid, Gizem");
MODULE_LICENSE("Dual BSD/GPL");

////////////////////////setting default key
struct vault_key_t vault_default_key;
vault_default_key.size = 4;
strcpy(vault_default_key.buf, vault_default_key_text);
////////////////////////setting default key


struct vault_text{
    char * cipher;
    size_t size;
}

struct vault_dev {
    struct vault_text * text;
    struct semaphore sem;
    struct cdev cdev;
};

struct vault_dev * vault_devices;


int alphabet_order(char input){
    int order = input - 96;
    if(order > 0 && order < 27) return order;
    else return -1;
}


int vault_trim(struct vault_dev *dev)
{
    if(dev->text){
    	if (dev->text->cipher) {
        	kfree(dev->text->cipher);
	    }
	}
    dev->text = NULL;
    return 0;
}

void change_key(struct vault_key_t * new_key){
    if(!new_key) return;
    vault_default_key.size = new_key -> size;
    strcpy(vault_default_key.buf, new_key -> buf);
}

void delete_vault(struct file * filp){
    struct messagebox_dev *dev = filp->private_data;
    vault_trim(dev);
}


int* get_permutation_function(char keytemp[], int key_length){
    char key[key_length];  // should be redeclared, otherwise throws seg. fault
    strcpy(key, keytemp);  // redefine

    int *p_function = kmalloc (sizeof (int) * 100, GFP_KERNEL);
    char min = 'z';
    int min_index;
    char smin_index[2];

    
    for(int i=0; i<key_length; i++){
        for(int j=0; j<key_length; j++){
            char temp = key[j];

            if(temp < min){
                min = temp;
                min_index = j;
            }
        }
        
        key[min_index] = 'z';  //done with ith element
        min = 'z';
        p_function[min_index] = i + 1 + '0';
    }
    return p_function;
}



char* encrypt_text(char tempText[], int text_length, int tempKey[], int key_length){
    char text[text_length];  // should be redeclared, otherwise throws seg. fault
    strcpy(text, tempText);  // redefine
    
    int key[key_length];  // should be redeclared, otherwise throws seg. fault
    int i = 0;
    for(; i<key_length; i++){
        key[i] = tempKey[i];
    }
    
    char *substr = kmalloc (sizeof (char) * key_length, GFP_KERNEL);
    char *encryptedText = kmalloc (sizeof (char) * text_length, GFP_KERNEL);
    strcpy(encryptedText, text);
    
    int loop_ctr = text_length / key_length;
    if(text_length % key_length != 0) loop_ctr++;

    for(int i=0; i<loop_ctr; i++){
        strncpy(substr, text+(i*key_length),key_length);
        for(int j=0; j<key_length; j++){
            encryptedText[j+i*key_length] = substr[key[j]-1];
        }
    }
    return encryptedText;
}



char* decrypt_text(char tempText[], int text_length, int tempKey[], int key_length){
    char text[text_length];  // should be redeclared, otherwise throws seg. fault
    strcpy(text, tempText);  // redefine
       

    int key[key_length];  // should be redeclared, otherwise throws seg. fault
    int i = 0;
    for(; i<key_length; i++){
        key[i] = tempKey[i];
    }


    char *substr = kmalloc (sizeof (char) * key_length, GFP_KERNEL);
    char *decryptedText = kmalloc (sizeof (char) * text_length, GFP_KERNEL);
    strcpy(decryptedText, text);
    
    int loop_ctr = text_length / key_length;
    if(text_length % key_length != 0) loop_ctr++;

    for(int i=0; i<loop_ctr; i++){
        strncpy(substr, text+(i*key_length),key_length);
        for(int j=0; j<key_length; j++){
            decryptedText[key[j]-1 + i*key_length] = substr[j];
        }
    }
    return decryptedText;
}




////////////////////////vault functions

int vault_open(struct inode *inode, struct file *filp)
{
    struct vault_dev *dev;

    dev = container_of(inode->i_cdev, struct vault_dev, cdev);
    filp->private_data = dev;

    /* trim the device if open was write-only */
    if ((filp->f_flags & O_ACCMODE) == O_WRONLY) {
        if (down_interruptible(&dev->sem))
            return -ERESTARTSYS;
        vault_trim(dev);
        up(&dev->sem);
    }
    return 0;
}


int vault_release(struct inode *inode, struct file *filp)
{
    return 0;
}


ssize_t vault_read(struct file *filp, char __user *buf, size_t count,
                   loff_t *f_pos)
{
    struct vault_dev *dev = filp->private_data;
    ssize_t retval = 0;

    char *local_buffer;
    local_buffer = kmalloc(count, GFP_KERNEL);

    if (down_interruptible(&dev->sem))
        return -ERESTARTSYS;

    if (*f_pos >= dev->text->size)
        goto out;
 
    if (dev->text == NULL || *f_pos == 0)
        goto out;


    char * decrypted_text = decrypt_text(dev->text->cipher, dev->text->size, vault_default_key->buf, vault_default_key->size);
    memcpy(decrypted_text, local_buffer, dev->text->size);
    
    if (copy_to_user(buf, local_buffer, count)) {
        retval = -EFAULT;
        goto out;
    }
    *f_pos -= count;
    retval = count;

  out:
    up(&dev->sem);
    return retval;
}


ssize_t vault_write(struct file *filp, const char __user *buf, size_t count,
                    loff_t *f_pos)
{
    struct vault_dev *dev = filp->private_data;

    ssize_t retval = -ENOMEM;

    if (down_interruptible(&dev->sem))
        return -ERESTARTSYS;

    if (*f_pos >= 0) {
        retval = 0;
        goto out;
    }

    //copy buffer to a local variable
    char *local_buffer;
    local_buffer = kmalloc(count, GFP_KERNEL);
    copy_from_user(local_buffer, buf, count);
    int i = 0;
    for(; i<count; i++){
        if(alphabet_order(local_buffer[i]) == -1) goto out;
    }

    //create an encrypted text struct to put it into the device
    struct vault_text * new_text = kmalloc(sizeof(struct vault_text), GFP_KERNEL);
    
    //get permutation function (int array)
    int* p_function = get_permutation_function(vault_default_key->buf, vault_default_key->size);
    
    //get encrypted text
    char* encrypted_text = encrypt_text(local_buffer, count, p_function, vault_default_key->size);

    //assign encrypted text and its size to the struct
    new_text->cipher = encrypted_text;
    new_text->size = strlen(encrypted_text);

    //device's pointer points to the new encrypted text struct
    dev->text = new_text;


    *f_pos += count;
    retval = count;



  out:
    up(&dev->sem);
    return retval;
}

long vault_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{

	int err = 0, tmp;
	int retval = 0;

	/*
	 * extract the type and number bitfields, and don't decode
	 * wrong cmds: return ENOTTY (inappropriate ioctl) before access_ok()
	 */
	if (_IOC_TYPE(cmd) != VAULT_IOC_MAGIC) return -ENOTTY;
	if (_IOC_NR(cmd) > VAULT_IOC_MAXNR) return -ENOTTY;

	/*
	 * the direction is a bitmask, and VERIFY_WRITE catches R/W
	 * transfers. `Type' is user-oriented, while
	 * access_ok is kernel-oriented, so the concept of "read" and
	 * "write" is reversed
	 */
	if (_IOC_DIR(cmd) & _IOC_READ)
    
        #if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
            err = !access_ok((void __user *)arg, _IOC_SIZE(cmd));
        #else
            err = !access_ok(VERIFY_WRITE, (void __user *)arg, _IOC_SIZE(cmd));
        #endif
	else if (_IOC_DIR(cmd) & _IOC_WRITE)
        #if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
            err =  !access_ok((void __user *)arg, _IOC_SIZE(cmd));
        #else
            err =  !access_ok(VERIFY_READ, (void __user *)arg, _IOC_SIZE(cmd));
        #endif
	if (err) return -EFAULT;

	switch(cmd) {


	  case VAULT_SET_KEY: 
		if (! capable (CAP_SYS_ADMIN)) return -EPERM;
		struct vault_key_t key;
		if (copy_from_user(&key, (char __user*)arg, sizeof(vault_key_t))) return -EFAULT;		
        	change_key(&key)
        break;


	  case VAULT_CLEAR_TEXT: 
		if (! capable (CAP_SYS_ADMIN))
			return -EPERM;
        	delete_vault(filp);



	  default:  /* redundant, as cmd was checked against MAXNR */
		return -ENOTTY;
	}
	return retval;
}


loff_t vault_llseek(struct file *filp, loff_t off, int whence)
{
    struct vault_dev *dev = filp->private_data;
    loff_t newpos;

    switch(whence) {
        case 0: /* SEEK_SET */
            newpos = off;
            break;

        case 1: /* SEEK_CUR */
            newpos = filp->f_pos + off;
            break;

        case 2: /* SEEK_END */
            newpos = dev->text->size + off;
            break;

        default: /* can't happen */
            return -EINVAL;
    }
    if (newpos < 0)
        return -EINVAL;
    filp->f_pos = newpos;
    return newpos;
}


struct file_operations vault_fops = {
    .owner =    THIS_MODULE,
    .llseek =   vault_llseek,
    .read =     vault_read,
    .write =    vault_write,
    .unlocked_ioctl =  vault_ioctl,
    .open =     vault_open,
    .release =  vault_release,
};


void vault_cleanup_module(void)
{
    int i;
    dev_t devno = MKDEV(vault_major, vault_minor);

    if (vault_devices) {
        for (i = 0; i < vault_nr_devs; i++) {
            vault_trim(vault_devices + i);
            cdev_del(&vault_devices[i].cdev);
        }
    kfree(vault_devices);
    }

    unregister_chrdev_region(devno, vault_nr_devs);
}


int vault_init_module(void)
{
    int result, i;
    int err;
    dev_t devno = 0;
    struct vault_dev *dev;

    if (vault_major) {
        devno = MKDEV(vault_major, vault_minor);
        result = register_chrdev_region(devno, vault_nr_devs, "vault");
    } else {
        result = alloc_chrdev_region(&devno, vault_minor, vault_nr_devs,
                                     "vault");
        vault_major = MAJOR(devno);
    }
    if (result < 0) {
        printk(KERN_WARNING "vault: can't get major %d\n", vault_major);
        return result;
    }

    vault_devices = kmalloc(vault_nr_devs * sizeof(struct vault_dev),
                            GFP_KERNEL);
    if (!vault_devices) {
        result = -ENOMEM;
        goto fail;
    }
    memset(vault_devices, 0, vault_nr_devs * sizeof(struct vault_dev));

    /* Initialize each device. */
    for (i = 0; i < vault_nr_devs; i++) {
        dev = &vault_devices[i];
        sema_init(&dev->sem,1);
        devno = MKDEV(vault_major, vault_minor + i);
        cdev_init(&dev->cdev, &vault_fops);
        dev->cdev.owner = THIS_MODULE;
        dev->cdev.ops = &vault_fops;
        err = cdev_add(&dev->cdev, devno, 1);
        if (err)
            printk(KERN_NOTICE "Error %d adding vault%d", err, i);
    }

    return 0; /* succeed */

  fail:
    vault_cleanup_module();
    return result;
}

module_init(vault_init_module);
module_exit(vault_cleanup_module);
