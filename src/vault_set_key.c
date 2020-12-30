#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <errno.h>

#include "vault_ioctl.h"

int main(int argc, char *argv[]){

    vault_key_t key;

    strncpy(key.buf, argv[1], strlen(argv[1]));
    key.size = strlen(key.buf);

    char path[80];
    strncpy(path, argv[2], strlen(argv[2]));

    int fd = open(path, O_RDWR);
    int status = ioctl(fd, VAULT_SET_KEY, &key);
	
    if(status == -1) perror("Can't change the key!");
		
    return status;
}
