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
	$(CC) -o $@ cpu.$O $(LIBS) `pkg-config $(OPENSSL) --libs` $(LDFLAGS)

login_-dp9ik: bsd.$O $(LIBS)
	$(CC) -o $@ bsd.$O $(LIBS)

pam_p9.so: pam.$O $(LIBS)
	$(CC) -shared -o $@ pam.$O $(LIBS)

cpu.$O: cpu.c
	$(CC) `pkg-config $(OPENSSL) --cflags` $(CFLAGS) $< -o $@

mount.9ptls: mount.$O
	$(CC) $(LDFLAGS) -o $@ $<

%.$O: %.c
	$(CC) $(CFLAGS) $< -o $@

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
	rm -f *.o lib*/*.o lib*/*.a tlsclient pam_p9.so login_-dp9ik mount.9ptls

linux.tar.gz: tlsclient pam_p9.so mount.9ptls tlsclient.1 mount.9ptls.8
	tar cf - $^ | gzip > $@

tlsclient.obsd:
	OPENSSL=eopenssl11 LDFLAGS="$(LDFLAGS) -Xlinker --rpath=/usr/local/lib/eopenssl11/" $(MAKE) tlsclient
	mv tlsclient tlsclient.obsd

obsd.tar.gz: tlsclient.obsd login_-dp9ik tlsclient.1 login_-dp9ik.8
	tar cf - tlsclient.obsd login_-dp9ik tlsclient.1 login_-dp9ik.8 | gzip > $@

.PHONY: tlsclient.install
tlsclient.install: tlsclient tlsclient.1
	mkdir -p $(PREFIX)/bin $(PREFIX)/share/man/man1
	install -m755 tlsclient $(PREFIX)/bin/
	install -m644 tlsclient.1 $(PREFIX)/share/man/man1/

.PHONY: mount.9ptls.install
mount.9ptls.install: mount.9ptls mount.9ptls.8
	mkdir -p $(PREFIX)/share/man/man8/ $(SBIN)
	install -m755 mount.9ptls $(SBIN)
	install -m644 mount.9ptls.8 $(PREFIX)/share/man/man8/

.PHONY: pam.install
pam.install: pam_p9.so
	mkdir -p $(PREFIX)/lib/security
	install -m755 pam_p9.so $(PREFIX)/lib/security

.PHONY: tlsclient.obsd.install
tlsclient.obsd.install: tlsclient.obsd login_-dp9ik tlsclient.1 login_-dp9ik.8
	install tlsclient.obsd $(PREFIX)/bin/tlsclient
	install tlsclient.1 $(PREFIX)/share/man/man1/
	install login_-dp9ik.8 $(PREFIX)/share/man/man8/
	install -d $(PREFIX)/libexec/auth
	install -g auth login_-dp9ik $(PREFIX)/libexec/auth/
	install -d $(PREFIX)/libexec/git
	install git-remote-hjgit $(PREFIX)/libexec/git
