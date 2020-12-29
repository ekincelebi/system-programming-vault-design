#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <errno.h>

#include "vault_ioctl.h"

int main(int argc, char *argv[]){

    char path[80];
    strncpy(path, argv[1], strlen(argv[1]));

    int fd = open(path, O_RDWR);
    int status = ioctl(fd, VAULT_CLEAR_TEXT);
	
    if(status == -1) perror("Can't clear the text from the device!");
		
    return status;
}
