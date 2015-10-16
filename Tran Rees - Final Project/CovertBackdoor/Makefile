CC = gcc
CFLAGS = -Wall -ggdb
PFLAGS = -lpcap

project: helperFunctions.o controller.c controller.h backdoor.c backdoor.h
	$(CC) $(CFLAGS) $(PFLAGS) helperFunctions.o controller.c -o controller
	$(CC) $(CFLAGS) $(PFLAGS) helperFunctions.o backdoor.c -o backdoor

controller: helperFunctions.o controller.c controller.h
	$(CC) $(CFLAGS) $(PFLAGS) sharedLibrary.o controller.c -o controller

backdoor: helperFunctions.o backdoor.c backdoor.h
	$(CC) $(CFLAGS) $(PFLAGS) helperFunctions.o backdoor.c -o backdoor

helperFunctions: helperFunctions.c helperFunctions.h
	$(CC) $(CFLAGS) -O -c helperFunctions.c

clean:
	rm -f *.o *.bak *.out ex
