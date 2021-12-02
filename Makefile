PREFIX=x86_64-linux-musl
CC=./$(PREFIX)-cross/bin/$(PREFIX)-gcc
CFLAGS=-static

all: runner.elf payload-x86_64.bin exec_payload-x86_64.bin

runner.elf: runner.c
	$(CC) -g -static runner.c -o runner.elf

%.bin: %.o
	objcopy -O binary -j .text $< $@

clean: 
	rm -f *.elf *.o *.bin
