
passvault: cipher_utils.o main.o file_io.o
	gcc -o passvault  cipher_utils.o main.o file_io.o  -lssl -lcrypto

cipher_utils.o: cipher_utils.c
	gcc -c cipher_utils.c

file_io.o: file_io.c
	gcc -c file_io.c
 
main.o: main.c
	gcc -c main.c

clean:
	rm -rf *.o passvault

