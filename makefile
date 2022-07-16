all: main

main: main.o functions64.o
	ld  main.o functions64.o -o main

main.o: main.asm
	nasm -g -f elf64 -F dwarf main.asm -l main.lst

clean:
	rm -f ./main.o || true
	rm -f ./main.lst || true
	rm -f ./main || true
