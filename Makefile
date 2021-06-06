#####
## BUILD
#####
CC=riscv64-unknown-elf-gcc
CFLAGS=-Wall -Wextra -pedantic -Wextra -O0 -g
CFLAGS+=-static -ffreestanding -nostdlib -fno-rtti -fno-exceptions
CFLAGS+=-march=rv64gc -mabi=lp64d
INCLUDES=
LINKER_SCRIPT=-Tlink.ld
TYPE=debug
RUST_TARGET=./target/riscv64gc-unknown-none-elf/$(TYPE)
LIBS=-L$(RUST_TARGET)
SOURCES_ASM=$(wildcard src/cpu/*.s)
LIB=-lcorgo -lgcc
OUT=os.elf

#####
## QEMU
#####
QEMU=qemu-system-riscv64
MACH=virt
CPU=rv64
CPUS=4
MEM=128M
DISK=hdd.dsk
DRIVE= -drive if=none,format=raw,file=$(DISK),id=foo -device virtio-blk-device,scsi=off,drive=foo
OPTS=-nographic -serial mon:stdio -bios none -device virtio-rng-device -device virtio-gpu-device
OPTS+=-device virtio-net-device -device virtio-tablet-device -device virtio-keyboard-device
#DRIVE=


all: $(DISK)
	cargo build
	$(CC) $(CFLAGS) $(LINKER_SCRIPT) $(INCLUDES) -o $(OUT) $(SOURCES_ASM) $(LIBS) $(LIB)

$(DISK):
	dd if=/dev/urandom of=$@ bs=1M count=32
	
run: all
	$(QEMU) -machine $(MACH) -cpu $(CPU) -smp $(CPUS) -m $(MEM) $(DRIVE) $(OPTS) -kernel $(OUT)


.PHONY: clean
clean:
	cargo clean
	rm -f $(OUT) $(DISK)
