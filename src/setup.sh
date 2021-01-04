#!/bin/bash

make

if [ "$(ls /dev | grep vault | wc -l)" -ge "1" ]
then	
	rmmod vault
	rm -r /dev/vault*
fi

insmod ./vault.ko

MOD_NUMBER=$(grep vault /proc/devices | cut -d' ' -f1)

mknod /dev/vault0 c $MOD_NUMBER 0

gcc vault_set_key.c -o VSK

gcc vault_clear_text.c -o VCT

./test_initial_run.sh

