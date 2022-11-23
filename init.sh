#!/bin/sh

clang -Wall -g -O3 -DFTP_SERV ftp_serv.c -o ftp_serv && clang -Wall -g -O3 ftp_client.c -o ftp_client
