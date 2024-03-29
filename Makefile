# Compiler setup
CC      = g++
LDLIBS  = -lcrypto -lkeccak -lm
CFLAGS  = -march=native -mtune=native -O3 -fomit-frame-pointer -fwrapv -DNIST_KAT_GENERATION -Wmissing-declarations

# Build the application to generate the KATs
PQCgenKAT_encrypt:
	@$(CC) $(CFLAGS) -o $@ *.c $(LDLIBS)

# Clean build artefact
clean:
	@rm -f PQCgenKAT_encrypt

.PHONY: clean
