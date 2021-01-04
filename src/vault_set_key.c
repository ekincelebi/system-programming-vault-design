#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <string.h>

#include "vault_ioctl.h"

int alphabet_order(char input){
    int order = input - 96;
    if(order > 0 && order < 27) return order;
    else return -1;
}

int main(int argc, char *argv[]){

    vault_key_t key;
    int i = 0;

    strcpy(key.buf, (char*)argv[1]);
    key.size = strlen(key.buf);

    printf("Key: %s, Key Size: %d\n", key.buf, key.size);

    for(i = 0; i<key.size; i++){
        if(alphabet_order(key.buf[i]) == -1){
            printf("Your key should only consist of lowercase English alphabet. Returning.\n");
            return 0;
        }
    }

    int fd = open(argv[2], O_RDWR);

    if(fd == -1){
        perror("Cannot open the device!");
        return fd;
    }

    int status = ioctl(fd, VAULT_SET_KEY, &key);
	
    if(status == -1) perror("Cannot change the key!");
		
    return status;
}
