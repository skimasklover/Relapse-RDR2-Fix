ifndef PS5_PAYLOAD_SDK
$(error Set PS5_PAYLOAD_SDK to your installed PS5 Payload SDK directory)
endif
include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk

CFLAGS := -Wall -Werror -g
ELF := rdr2-service-id-whitespace-fix-debug.elf
RESTORE_ELF := rdr2-service-id-whitespace-restore-debug.elf

.PHONY: all restore clean
all: $(ELF)
$(ELF): src/payload.c src/signatures.h
	$(CC) $(CFLAGS) -o $@ src/payload.c
restore: $(RESTORE_ELF)
$(RESTORE_ELF): src/payload.c src/signatures.h
	$(CC) $(CFLAGS) -DRESTORE=1 -o $@ src/payload.c
clean:
	rm -f $(ELF) $(RESTORE_ELF)
