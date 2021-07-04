ROOT=.

include ./Make.config

LIBS=\
	libauthsrv/libauthsrv.a\
	libmp/libmp.a\
	libc/libc.a\
	libsec/libsec.a\

OFILES=cpu.$O p9any.$O

default: $(TARG)
$(TARG): $(LIBS) $(OFILES)
	$(CC) `pkg-config openssl --libs` $(LDFLAGS) -o $(TARG) $(OFILES) $(LIBS) $(LDADD)

pam_p9.so: $(LIBS) p9any.$O pam.$O
	$(CC) -shared -o pam_p9.so p9any.$O pam.$O $(LIBS)

cpu.$O: cpu.c
	$(CC) `pkg-config openssl --cflags` $(CFLAGS) cpu.c -o cpu.o

p9any.$O: p9any.c
	$(CC) $(CFLAGS) p9any.c -o p9any.o

pam.$O: pam.c
	$(CC) $(CFLAGS) pam.c -o pam.o

.PHONY: clean
clean:
	rm -f *.o */*.o */*.a *.a $(TARG) pam_p9.so

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
