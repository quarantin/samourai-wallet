PROG := poc

all:
	gcc $(PROG).c parse.c -lssl -lcrypto -lcjson -o $(PROG)

clean:
	rm -f $(PROG)
