#include <stddef.h>
#include <stdint.h>
#include "file.h"

void delay(uint32_t count) {
    for(uint32_t i = 0; i < count; i++) {
        
    }
}

void
__attribute__((noreturn))
__attribute__((section(".start")))
_start(void) {

	/*
		INSERT CODE BELOW THIS LINE
	*/
  const char *filename = "drugi.txt\0";
  int fd = my_open(filename);
	if(fd < 0) {
		for (;;)
			asm("hlt");
	}
  my_write(fd, "Hello, This is from guest 4");
  delay(10000000);
  char buffer[100];
  my_read(fd, buffer, 12, 7);
  for(size_t i = 0; i < 12; i++) {
    outb(0xE9, buffer[i]);
  }
  my_close(fd);
  int fd2 = my_open("deljeni.txt\0");
	if(fd2 < 0) {
		for (;;)
			asm("hlt");
	}
	my_read(fd2, buffer, 10, 10);
	for(size_t i = 0; i < 10; i++) {
		outb(0xE9, buffer[i]);
	}
	int fd3 = my_open("slova.txt\0");
	if(fd3 < 0) {
		for (;;)
			asm("hlt");
	}
	my_read(fd3, buffer, 1, 20);
	buffer[1] = '\0';
	my_write(fd2, "Hello, This is from guest 4 and i read letter:");
	my_write(fd2, buffer);
	my_close(fd3);
	my_close(fd2);
	/*
		INSERT CODE ABOVE THIS LINE
	*/

	for (;;)
		asm("hlt");
}
