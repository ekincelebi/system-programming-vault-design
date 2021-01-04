#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <errno.h>

#include "vault_ioctl.h"

int main(int argc, char *argv[]){

    vault_key_t key;

    strcpy(key.buf, (char*)argv[1]);
    key.size = strlen(key.buf);

    printf("Key: %s, Key Size: %d\n", key.buf, key.size);

    int fd = open(argv[2], O_RDWR);

    if(fd == -1){
        perror("Cannot open the device!");
        return fd;
    }

    int status = ioctl(fd, VAULT_SET_KEY, &key);
	
    if(status == -1) perror("Cannot change the key!");
		
    return status;
}
