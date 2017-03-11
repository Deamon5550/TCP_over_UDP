
CC=gcc
CFLAGS=-Wall

default: clean httpsrv

httpsrv: rdpr.o rdps.o
	$(CC) $(CFLAGS) -o rdpr rdpr.o
	$(CC) $(CFLAGS) -o rdps rdps.o

rdpr: rdpr.o
	$(CC) $(CFLAGS) -o rdpr rdpr.o

rdps: rdps.o
	$(CC) $(CFLAGS) -o rdps rdps.o

rdpr.o: rdpr.c
	$(CC) $(CFLAGS) -c rdpr.c

rdps.o: rdps.c
	$(CC) $(CFLAGS) -c rdps.c

clean:
	$(RM) rdpr rdps *.o
