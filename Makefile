all: panthercrypt pantherdec

panthercrypt : panthercrypt.o
	gcc -o panthercrypt panthercrypt.o `libgcrypt-config --libs` #for linking the program with the library
panthercrypt1.o : panthercrypt.c
	gcc -c panthercrypt.c `libgcrypt-config --cflags` #to ensure that the compiler can find the Libgcrypt header file
pantherdec : pantherdec.o
	gcc -o pantherdec pantherdec.o `libgcrypt-config --libs`
pantherdec.o : pantherdec.c
	gcc -c pantherdec.c `libgcrypt-config --cflags`
clean:
	rm  panthercrypt.o panthercrypt pantherdec.o pantherdec
