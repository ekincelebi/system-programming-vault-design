#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <string.h>

#include "vault_ioctl.h"

int main(int argc, char *argv[]){

    int fd = open(argv[1], O_RDWR);

    if(fd == -1){
        perror("Cannot open the device to clear!");
        return fd;
    }

    int status = ioctl(fd, VAULT_CLEAR_TEXT);
	
    if(status == -1) perror("Cannot clear the text from the device!");
		
    return status;
}
