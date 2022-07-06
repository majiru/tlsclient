ROOT=.

include ./Make.config

LIBS=\
	p9any.$O\
	libauthsrv/libauthsrv.a\
	libmp/libmp.a\
	libc/libc.a\
	libsec/libsec.a\

default: tlsclient

tlsclient: cpu.$O $(LIBS)
	$(CC) `pkg-config $(OPENSSL) --libs` -o $@ $^

login_-dp9ik: bsd.$O $(LIBS)
	$(CC) -o $@ $^

pam_p9.so: pam.$O $(LIBS)
	$(CC) -shared -o $@ $^

%.$O: %.c
	$(CC) `pkg-config $(OPENSSL) --cflags` $(CFLAGS) $< -o $@

libauthsrv/libauthsrv.a:
	(cd libauthsrv; $(MAKE))

libmp/libmp.a:
	(cd libmp; $(MAKE))

libc/libc.a:
	(cd libc; $(MAKE))

libsec/libsec.a:
	(cd libsec; $(MAKE))

.PHONY: clean
clean:
	rm -f *.o lib*/*.o lib*/*.a tlsclient pam_p9.so login_-dp9ik

linux.tar.gz: tlsclient pam_p9.so tlsclient.1
	tar c $^ | gzip > $@

obsd.tar.gz: tlsclient login_-dp9ik tlsclient.1
	tar c $^ | gzip > $@

.PHONY: tlsclient.install
tlsclient.install: tlsclient tlsclient.1
	cp tlsclient $(PREFIX)/bin
	cp tlsclient.1 $(PREFIX)/man/man1/
