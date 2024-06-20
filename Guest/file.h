#ifndef _FILE_H
#define _FILE_H

#include <stddef.h>
#include <stdint.h>

#define PORT 0x0278

static void outb(uint16_t port, uint8_t value) {
    asm("outb %0,%1" : /* empty */ : "a" (value), "Nd" (port) : "memory");
}

static void outl(uint16_t port, uint32_t value) {
    asm("outl %0,%1" : /* empty */ : "a" (value), "Nd" (port) : "memory");
}

static uint32_t inl(uint16_t port) {
    uint32_t value;
    asm("inl %1,%0" : "=a" (value) : "Nd" (port) : "memory");
    return value;
}

int my_open(const char *filename) {
    outb(PORT, 1); // OPEN 
    while (*filename) {
        outb(PORT, *filename++);
    }
    outb(PORT, '\0'); 

    return inl(PORT); // Wait for the hypervisor to finish opening the file
}

void my_close(int fd) {
    outb(PORT, 2); // CLOSE
    outl(PORT, fd);
}

void my_read(int fd, char *buffer, size_t count, size_t offset) {
    outb(PORT, 3); // READ
    outl(PORT, fd);
    outl(PORT, count);
    outl(PORT, offset);
    // TODO: Receive the read data from the hypervisor
    for(size_t i = 0; i < count; i++) {
        buffer[i] = inl(PORT);
    }
}

void my_write(int fd, const char *data) {
    outb(PORT, 4); // WRITE
    outl(PORT, fd);
    while (*data) {
        outb(PORT, *data++);
    }
    outb(PORT, '\0'); 
}

#endif