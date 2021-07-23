/*
 * cpu.c - Make a connection to a cpu server
 */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <openssl/ssl.h>

#include <u.h>
#include <args.h>
#include <libc.h>
#include <auth.h>
#include <authsrv.h>
#include <libsec.h>

#include "fncs.h"

char *argv0;

char *authserver;
static char *user, *pass;

SSL_CTX *ssl_ctx;
SSL *ssl_conn;

//callback needs access to ai returned from p9any
static AuthInfo *ai;

static uint
psk_client_cb(SSL *ssl, const char *hint, char *identity, uint max_iden_len, uchar *psk, uint max_psk_len)
{
	uint nsecret = ai->nsecret;
	char i[] = "p9secret";
	if(max_iden_len < sizeof i || max_psk_len < ai->nsecret)
		sysfatal("psk buffers are too small");
	memcpy(identity, i, sizeof i);
	memcpy(psk, ai->secret, ai->nsecret);
	memset(ai, 0, sizeof *ai);
	return nsecret;
}

/*
 * p9any authentication followed by tls-psk encryption
 */
static int
p9authtls(int fd)
{
	ai = p9any(user, pass, fd);
	if(ai == nil)
		sysfatal("can't authenticate");

	SSL_set_fd(ssl_conn, fd);
	if(SSL_connect(ssl_conn) < 0)
		sysfatal("ssl could not connect");

	return fd;
}

typedef size_t (*iofunc)(int, void*, size_t);
size_t tls_send(int f, void *b, size_t n) { return SSL_write(ssl_conn, b, n); }
size_t tls_recv(int f, void *b, size_t n) { return SSL_read(ssl_conn, b, n); }
size_t s_send(int f, void *b, size_t n) { return write(f, b, n); }
size_t s_recv(int f, void *b, size_t n) { return read(f, b, n); }

void
xfer(int from, int to, iofunc recvf, iofunc sendf)
{
	char buf[12*1024];
	size_t n;
	
	while((n = recvf(from, buf, sizeof buf)) > 0){
		if(sendf(to, buf, n) < 0)
			break;
	}

}

void
usage(void)
{
	fprint(2, "Usage: %s [ -R ] [ -u user ] [ -h host ] [ -a authserver ] -p port cmd...\n", argv0);
	exits("usage");
}

int
main(int argc, char **argv)
{
	int Rflag;
	int fd;
	char buf2[1024];
	char buf[1024];
	size_t n;
	char *port;
	char *host;
	int pin[2];
	int pout[2];
	int infd, outfd;
	char *srv = nil;
	int i;
	pid_t execc, xferc;

	execc = xferc = 0;
	Rflag = 0;
	infd = 0;
	outfd = 1;
	user = getenv("USER");	
	host = getenv("CPU");
	authserver = getenv("AUTH");
	pass = getenv("PASS");
	port = nil;

	ARGBEGIN {
		case 'u': user = EARGF(usage()); break;
		case 'h': host = EARGF(usage()); break;
		case 'a': authserver = EARGF(usage()); break;
		case 'p': port = EARGF(usage()); break;
		case 'R': Rflag++; break;
		case 's': srv = EARGF(usage()); break;
	} ARGEND

	if(Rflag || srv != nil)
		port = "17019";

	if(user == nil || host == nil || authserver == nil || port == nil)
		usage();

	if(pass == nil)
		pass = getpass("password:");

	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	ssl_ctx = SSL_CTX_new(TLSv1_2_client_method());
	SSL_CTX_set_psk_client_callback(ssl_ctx, psk_client_cb);
	if(ssl_ctx == nil)
		sysfatal("could not init openssl");
	ssl_conn = SSL_new(ssl_ctx);


	fd = unix_dial(host, port);
	if(fd < 0){
		sysfatal("Failed to connect to the client");
	}

	p9authtls(fd);

	if(!Rflag || srv != nil){
		pipe(pin);
		pipe(pout);
		switch((execc = fork())){
		case -1:
			sysfatal("fork");
		case 0:
			close(pin[1]);
			close(pout[0]);
			dup2(pin[0], 0);
			dup2(pout[1], 1);
			execvp(argv[0], argv);
			sysfatal("exec");
		}
		close(pout[1]);
		close(pin[0]);
		infd = pout[0];
		outfd = pin[1];
		if(srv != nil){
			snprint(buf, sizeof buf - 1, "bind '#|' /n/p; <>[3]/n/p/data1 { echo 3 > /srv/%s; cat /n/p/data & cat > /n/p/data}\n", srv);
			goto rcpu;
		}
	}

	if(Rflag) {
		for(i=0,n=0; i<argc; i++)
			n += snprint(buf+n, sizeof buf - n - 1, "%s ", argv[i]);
		if(n <= 0)
			usage();
		buf[n-1] = '\n';
		buf[n] = '\0';
rcpu:
		i = strlen(buf);
		snprint(buf2, sizeof buf2, "%7d\n", i);
		tls_send(-1, buf2, strlen(buf2));
		tls_send(-1, buf, i);
	}

	switch((xferc = fork())){
	case -1:
		sysfatal("fork");
	case 0:
		xfer(infd, -1, s_recv, tls_send);
		break;
	default:
		xfer(-1, outfd, tls_recv, s_send);
		break;
	}
	
	if(xferc)
		kill(xferc, SIGTERM);
	if(execc)
		kill(execc, SIGTERM);
}

