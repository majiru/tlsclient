ROOT=.

include ./Make.config

LIBS=\
	libauthsrv/libauthsrv.a\
	libmp/libmp.a\
	libc/libc.a\
	libsec/libsec.a\

OFILES=cpu.$O

default: $(TARG)
$(TARG): $(LIBS) $(OFILES)
	$(CC) `pkg-config openssl --libs` $(LDFLAGS) -o $(TARG) $(OFILES) $(LIBS) $(LDADD)

cpu.$O: cpu.c
	$(CC) `pkg-config openssl --cflags` $(CFLAGS) cpu.c -o cpu.o

.PHONY: clean
clean:
	rm -f *.o */*.o */*.a *.a $(TARG)

.PHONY: libauthsrv/libauthsrv.a
libauthsrv/libauthsrv.a:
	(cd libauthsrv; $(MAKE))

.PHONY: libmp/libmp.a
libmp/libmp.a:
	(cd libmp; $(MAKE))

.PHONY: libc/libc.a
libc/libc.a:
	(cd libc; $(MAKE))

.PHONY: libsec/libsec.a
libsec/libsec.a:
	(cd libsec; $(MAKE))
