#ifndef __VAULT_H
#define __VAULT_H

#include <linux/ioctl.h> /* needed for the _IOW etc stuff used later */

typedef struct vault_key{
    int size;
    char buf[40];
} vault_key_t;

#define VAULT_IOC_MAGIC  'k'
#define VAULT_SET_KEY _IOW(VAULT_IOC_MAGIC, 0, vault_key_t)
#define VAULT_CLEAR_TEXT _IO(VAULT_IOC_MAGIC, 1)
#define VAULT_IOC_MAXNR 1

#endif
