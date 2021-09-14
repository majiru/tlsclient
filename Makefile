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
	$(CC) `pkg-config $(OPENSSL) --libs` $(LDFLAGS) -o $(TARG) $(OFILES) $(LIBS) $(LDADD)

login_-dp9ik: $(LIBS) p9any.$O bsd.$O
	$(CC) -o login_-dp9ik p9any.$O bsd.$O $(LIBS)

pam_p9.so: $(LIBS) p9any.$O pam.$O
	$(CC) -shared -o pam_p9.so p9any.$O pam.$O $(LIBS)

cpu.$O: cpu.c
	$(CC) `pkg-config $(OPENSSL) --cflags` $(CFLAGS) cpu.c -o cpu.o

p9any.$O: p9any.c
	$(CC) $(CFLAGS) p9any.c -o p9any.o

pam.$O: pam.c
	$(CC) $(CFLAGS) pam.c -o pam.o

bsd.$O: bsd.c
	$(CC) $(CFLAGS) bsd.c -o bsd.o

.PHONY: clean
clean:
	rm -f *.o */*.o */*.a *.a $(TARG) pam_p9.so login_-dp9ik

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

linuxdist: tlsclient pam_p9.so 9cpu
	tar cf tlsclient.tar tlsclient pam_p9.so 9cpu
	gzip tlsclient.tar

obsddist: tlsclient login_-dp9ik 9cpu
	tar cf tlsclient-obsd.tar tlsclient 9cpu login_-dp9ik
	gzip tlsclient-obsd.tar
