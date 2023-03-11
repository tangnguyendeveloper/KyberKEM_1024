CC=$(shell which g++)
CFLAGS += -O3 -march=native -fomit-frame-pointer
CFLAGS_SHARE += -Wall -fPIC -O3 -march=native -fomit-frame-pointer
LDFLAGS=-lcrypto

SOURCES= cbd.c fips202.c indcpa.c kem.c ntt.c poly.c polyvec.c CRYSTALS_Kyber_1024.cpp reduce.c rng.c verify.c symmetric-shake.c KyberKEM1024.cpp
HEADERS= api.h cbd.h fips202.h indcpa.h ntt.h params.h poly.h polyvec.h reduce.h rng.h verify.h symmetric.h KyberKEM1024.hpp
SOURCES_SHARE= cbd.c fips202.c indcpa.c kem.c ntt.c poly.c polyvec.c Utilities_share.cpp reduce.c rng.c verify.c symmetric-shake.c KyberKEM1024.cpp


CRYSTALS_Kyber_1024_test: $(HEADERS) $(SOURCES)
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $(LDFLAGS)

CRYSTALS_KyberKEM_1024.so: $(HEADERS) $(SOURCES_SHARE)
	$(CC) -shared $(CFLAGS_SHARE) -o $@ $(SOURCES_SHARE) $(LDFLAGS)

.PHONY: clean all test shared

clean:
	-rm CRYSTALS_Kyber_1024_test
	-rm CRYSTALS_KyberKEM_1024.so

all: \
	CRYSTALS_Kyber_1024_test \
	CRYSTALS_KyberKEM_1024.so

test: CRYSTALS_Kyber_1024_test

shared: CRYSTALS_KyberKEM_1024.so