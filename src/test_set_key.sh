#!/bin/bash

argv=("$@")
argc=$#

if [ $argc -eq 1 ]
then
	for vault in /dev/vault*
	do
		./VSK $argv ${vault}
	done
else
	echo not enough input arguments
fi



