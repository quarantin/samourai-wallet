PROG := poc

all:
	gcc $(PROG).c parse.c -lssl -lcrypto -lcjson -o $(PROG)
	gcc -O2 -mno-avx simple.c -lssl -lcrypto -o simple


clean:
	rm -f $(PROG) simple
