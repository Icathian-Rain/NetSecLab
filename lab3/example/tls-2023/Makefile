all: 
	gcc -o tlsclient tlsclient.c -lssl -lcrypto 
	gcc -o tlsserver tlsserver.c -lssl -lcrypto 

clean: 
	rm -f tlsclient tlsserver 
	rm -f *~

