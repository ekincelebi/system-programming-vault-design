
## System Programming - Project 2 - Group 14

Linux kernel version: 3.13.0-32-generic


Bash version: 4.3.11(1)-release

### To install our project:


`$ sudo su`


`$ ./setup.sh`

### This script will run an initial test (`./test_initial_run.sh`) inside.

### To run several tests:


`
$ ./test_case.sh
`


### To clear text inside the vault


`
$ ./VCT ${device-name}
`


### To change the key for all vault devices under /dev (might not work correct)


`
$ ./test_set_key.sh ${new_key}
`


