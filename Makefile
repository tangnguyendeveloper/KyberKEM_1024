CC=$(shell which g++)
CFLAGS += -O3 -march=native -fomit-frame-pointer
LDFLAGS=-lcrypto

SOURCES= cbd.c fips202.c indcpa.c kem.c ntt.c poly.c polyvec.c CRYSTALS_Kyber_1024.cpp reduce.c rng.c verify.c symmetric-shake.c KyberKEM1024.cpp
HEADERS= api.h cbd.h fips202.h indcpa.h ntt.h params.h poly.h polyvec.h reduce.h rng.h verify.h symmetric.h KyberKEM1024.hpp

CRYSTALS_Kyber_1024: $(HEADERS) $(SOURCES)
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $(LDFLAGS)

.PHONY: clean

clean:
	-rm CRYSTALS_Kyber_1024

