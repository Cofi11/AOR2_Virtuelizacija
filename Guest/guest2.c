#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

static void outb(uint16_t port, uint8_t value) {
	asm("outb %0,%1" : /* empty */ : "a" (value), "Nd" (port) : "memory");
}

void delay(uint32_t count) {
	volatile int i;
	for (i = 0; i < count; i++) {
			/* Do nothing - just wait */
	}
}


void
__attribute__((noreturn))
__attribute__((section(".start")))
_start(void) {

	/*
		INSERT CODE BELOW THIS LINE
	*/
	const char *p;
	uint16_t port = 0xE9;
	uint8_t value = 'B';

	for (uint8_t i = 0; i < 10; i++){
		outb(0xE9, value);
    delay(200000000);
  }
	/*
		INSERT CODE ABOVE THIS LINE
	*/

	for (;;)
		asm("hlt");
}
