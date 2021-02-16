/*
 * cpu.c - Make a connection to a cpu server
 */
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <netinet/in.h>
#include <gnutls/gnutls.h>

#include <u.h>
#include <args.h>
#include <libc.h>
#include <auth.h>
#include <authsrv.h>
#include <libsec.h>


#define MaxStr 128

static void	usage(void);
static int	readstr(int, char*, int);
static AuthInfo *p9any(int);
static int	getkey(Authkey*, char*, char*, char*, char*);
static int	p9authtls(int);

static char	*host;

char *argv0;

char *authserver;
char *secstore;
char *user, *pass;
char secstorebuf[65536];
char *geometry;

gnutls_session_t session;

void errstr(char *s){}

int
unix_dial(char *host, char *port)
{
	int fd;
	struct sockaddr_in server;
	struct hostent *he;
	struct in_addr **addr_list;

	he = gethostbyname(host);
	if(he == nil){
		sysfatal("could not resolve %s", host);
	}
	fd = socket(AF_INET, SOCK_STREAM, 0);
	addr_list = (struct in_addr **) he->h_addr_list;
	server.sin_addr.s_addr = inet_addr(inet_ntoa(*addr_list[0]));
	server.sin_family = AF_INET;
	server.sin_port = htons(atoi(port));
	if(connect(fd, (struct sockaddr*)&server, sizeof(server)) < 0)
		return -1;
	return fd;
}


char*
estrdup(char *s)
{
	s = strdup(s);
	if(s == nil)
		sysfatal("out of memory");
	return s;
}

typedef size_t (*iofunc)(int, void*, size_t);
size_t tls_send(int f, void *b, size_t n) { return gnutls_record_send(session, b, n); }
size_t tls_recv(int f, void *b, size_t n) { return gnutls_record_recv(session, b, n); }
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
	fprint(2, "Usage: %s [-f] [ -u user ] [ -h host ] [ -a authserver ] -p port cmd...\n", argv0);
	exits("usage");
}

int
main(int argc, char **argv)
{
	int fd, res;
	char *cmd;
	char buf[1024];
	size_t n;
	char *port;
	int pin[2];
	int pout[2];
	int infd, outfd;
	pid_t execc, xferc;
	int consin, consout, consflag;

	execc = xferc = 0;
	consflag = 0;
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
		case 'f': consflag++; break;
	} ARGEND

	if(user == nil || host == nil || authserver == nil || port == nil)
		usage();

	if(pass == nil)
		pass = getpass("password:");

	gnutls_global_init();
	res = gnutls_init(&session, GNUTLS_CLIENT);
	if(res != GNUTLS_E_SUCCESS){
		sysfatal("could not init session");
	}

	if(*argv){
		pipe(pin);
		pipe(pout);
		if(consflag){
			/*
			 * Unix has no /dev/cons, so there is no way to read
			 * and write from the terminal if stdin and stdout
			 * are dup'd over with the socket. This gives a bit
			 * of a back door in to the orginal stdin and stdout.
			 */
			consin = dup(0);
			consout = dup(1);
		}
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
		if(consflag){
			/*
			 * For the sake of portability,
			 * send the "cons" fds as the first
			 * to lines to the child process to avoid
			 * having to assume the next two fds
			 */
			n = sprint(buf, "%d%d", consin, consout);
			write(pin[1], buf, n);
		}
	}

	fd = unix_dial(host, port);
	if(fd < 0){
		sysfatal("Failed to connect to the client");
	}

	p9authtls(fd);

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

int
readstr(int fd, char *str, int len)
{
	int n;

	while(len) {
		n = read(fd, str, 1);
		if(n < 0) 
			return -1;
		if(*str == '\0')
			return 0;
		str++;
		len--;
	}
	return -1;
}


/*
 * p9any authentication followed by tls-psk encryption
 */
static int
p9authtls(int fd)
{
	AuthInfo *ai;
	gnutls_psk_client_credentials_t cred;
	gnutls_datum_t key;
	const char *error = NULL;
	int res;

	ai = p9any(fd);
	if(ai == nil)
		sysfatal("can't authenticate: %r");

	if(gnutls_psk_allocate_client_credentials(&cred) != 0)
		sysfatal("can't allocate client creds");

	key.size = ai->nsecret;
	key.data = ai->secret;

	if(gnutls_psk_set_client_credentials(cred, "p9secret", &key, GNUTLS_PSK_KEY_RAW) != 0)
		sysfatal("can't set creds");
	if(gnutls_credentials_set(session, GNUTLS_CRD_PSK, cred) != 0)
		sysfatal("can't set creds 2");
	res = gnutls_priority_set_direct(
		session,
		"NONE:+VERS-TLS1.2:+SIGN-ALL:+MAC-ALL:+CHACHA20-POLY1305:+PSK:+CTYPE-ALL",
		&error
	);
	if (res != GNUTLS_E_SUCCESS) {
		sysfatal("gnutls_priority_set_direct() failed: %s", error);
	}
	gnutls_transport_set_int(session, fd);
	do {
		res = gnutls_handshake(session);
	} while ( res != 0 && !gnutls_error_is_fatal(res) );

	if (gnutls_error_is_fatal(res)) {
		sysfatal("Fatal error during handshake");
	}

	return fd;
}

int
authdial(char *net, char *dom)
{
	return unix_dial(authserver, "567");
}

static int
getastickets(Authkey *key, Ticketreq *tr, uchar *y, char *tbuf, int tbuflen)
{
	int asfd, rv;
	char *dom;

	dom = tr->authdom;
	asfd = authdial(nil, dom);
	if(asfd < 0)
		return -1;
	if(y != nil){
		PAKpriv p;

		rv = -1;
		tr->type = AuthPAK;
		if(_asrequest(asfd, tr) != 0 || write(asfd, y, PAKYLEN) != PAKYLEN)
			goto Out;

		authpak_new(&p, key, (uchar*)tbuf, 1);
		if(write(asfd, tbuf, PAKYLEN) != PAKYLEN)
			goto Out;

		if(_asrdresp(asfd, tbuf, 2*PAKYLEN) != 2*PAKYLEN)
			goto Out;
	
		memmove(y, tbuf, PAKYLEN);
		if(authpak_finish(&p, key, (uchar*)tbuf+PAKYLEN))
			goto Out;
	}
	tr->type = AuthTreq;
	rv = _asgetticket(asfd, tr, tbuf, tbuflen);
Out:
	close(asfd);
	return rv;
}

static int
mkservertickets(Authkey *key, Ticketreq *tr, uchar *y, char *tbuf, int tbuflen)
{
	Ticket t;
	int ret;

	if(strcmp(tr->authid, tr->hostid) != 0)
		return -1;
	memset(&t, 0, sizeof(t));
	ret = 0;
	if(y != nil){
		PAKpriv p;

		t.form = 1;
		memmove(tbuf, y, PAKYLEN);
		authpak_new(&p, key, y, 0);
		authpak_finish(&p, key, (uchar*)tbuf);
	}
	memmove(t.chal, tr->chal, CHALLEN);
	strcpy(t.cuid, tr->uid);
	strcpy(t.suid, tr->uid);
	genrandom((uchar*)t.key, sizeof(t.key));
	t.num = AuthTc;
	ret += convT2M(&t, tbuf+ret, tbuflen-ret, key);
	t.num = AuthTs;
	ret += convT2M(&t, tbuf+ret, tbuflen-ret, key);
	memset(&t, 0, sizeof(t));

	return ret;
}

static int
gettickets(Authkey *key, Ticketreq *tr, uchar *y, char *tbuf, int tbuflen)
{
	int ret;
	ret = getastickets(key, tr, y, tbuf, tbuflen);
	if(ret > 0)
		return ret;
	return mkservertickets(key, tr, y, tbuf, tbuflen);
}

AuthInfo*
p9any(int fd)
{
	char buf[1024], buf2[1024], *bbuf, *p, *proto, *dom;
	uchar crand[2*NONCELEN], cchal[CHALLEN], y[PAKYLEN];
	char tbuf[2*MAXTICKETLEN+MAXAUTHENTLEN+PAKYLEN], trbuf[TICKREQLEN+PAKYLEN];
	Authkey authkey;
	Authenticator auth;
	int i, n, m, v2, dp9ik;
	Ticketreq tr;
	Ticket t;
	AuthInfo *ai;

	if(readstr(fd, buf, sizeof buf) < 0)
		sysfatal("cannot read p9any negotiation: %r");
	bbuf = buf;
	v2 = 0;
	if(strncmp(buf, "v.2 ", 4) == 0){
		v2 = 1;
		bbuf += 4;
	}
	dp9ik = 0;
	proto = nil;
	while(bbuf != nil){
		if((p = strchr(bbuf, ' ')))
			*p++ = 0;
		if((dom = strchr(bbuf, '@')) == nil)
			sysfatal("bad p9any domain");
		*dom++ = 0;
		if(strcmp(bbuf, "p9sk1") == 0 || strcmp(bbuf, "dp9ik") == 0){
			proto = bbuf;
			if(strcmp(proto, "dp9ik") == 0){
				dp9ik = 1;
				break;
			}
		}
		bbuf = p;
	}
	if(proto == nil)
		sysfatal("server did not offer p9sk1 or dp9ik");
	proto = estrdup(proto);
	sprint(buf2, "%s %s", proto, dom);
	if(write(fd, buf2, strlen(buf2)+1) != strlen(buf2)+1)
		sysfatal("cannot write user/domain choice in p9any");
	if(v2){
		if(readstr(fd, buf, sizeof buf) < 0)
			sysfatal("cannot read OK in p9any: %r");
		if(memcmp(buf, "OK\0", 3) != 0)
			sysfatal("did not get OK in p9any: got %s", buf);
	}
	genrandom(crand, 2*NONCELEN);
	genrandom(cchal, CHALLEN);
	if(write(fd, cchal, CHALLEN) != CHALLEN)
		sysfatal("cannot write p9sk1 challenge: %r");

	n = TICKREQLEN;
	if(dp9ik)
		n += PAKYLEN;

	if(readn(fd, trbuf, n) != n || convM2TR(trbuf, TICKREQLEN, &tr) <= 0)
		sysfatal("cannot read ticket request in p9sk1: %r");

again:
	if(!getkey(&authkey, user, tr.authdom, proto, pass))
		sysfatal("no password");

	strecpy(tr.hostid, tr.hostid+sizeof tr.hostid, user);
	strecpy(tr.uid, tr.uid+sizeof tr.uid, user);

	if(dp9ik){
		memmove(y, trbuf+TICKREQLEN, PAKYLEN);
		n = gettickets(&authkey, &tr, y, tbuf, sizeof(tbuf));
	} else {
		n = gettickets(&authkey, &tr, nil, tbuf, sizeof(tbuf));
	}
	if(n <= 0)
		sysfatal("cannot get auth tickets in p9sk1: %r");

	m = convM2T(tbuf, n, &t, &authkey);
	if(m <= 0 || t.num != AuthTc){
		print("?password mismatch with auth server\n");
		if(pass != nil && *pass)
			sysfatal("wrong password");
		goto again;
	}
	n -= m;
	memmove(tbuf, tbuf+m, n);

	if(dp9ik && write(fd, y, PAKYLEN) != PAKYLEN)
		sysfatal("cannot send authpak public key back: %r");

	auth.num = AuthAc;
	memmove(auth.rand, crand, NONCELEN);
	memmove(auth.chal, tr.chal, CHALLEN);
	m = convA2M(&auth, tbuf+n, sizeof(tbuf)-n, &t);
	n += m;

	if(write(fd, tbuf, n) != n)
		sysfatal("cannot send ticket and authenticator back: %r");

	if((n=read(fd, tbuf, m)) != m || memcmp(tbuf, "cpu:", 4) == 0){
		if(n <= 4)
			sysfatal("cannot read authenticator");

		/*
		 * didn't send back authenticator:
		 * sent back fatal error message.
		 */
		memmove(buf, tbuf, n);
		i = readn(fd, buf+n, sizeof buf-n-1);
		if(i > 0)
			n += i;
		buf[n] = 0;
		sysfatal("server says: %s", buf);
	}
	
	if(convM2A(tbuf, n, &auth, &t) <= 0
	|| auth.num != AuthAs || tsmemcmp(auth.chal, cchal, CHALLEN) != 0){
		print("?you and auth server agree about password.\n");
		print("?server is confused.\n");
		sysfatal("server lies");
	}
	memmove(crand+NONCELEN, auth.rand, NONCELEN);

	// print("i am %s there.\n", t.suid);

	ai = mallocz(sizeof(AuthInfo), 1);
	ai->suid = estrdup(t.suid);
	ai->cuid = estrdup(t.cuid);
	if(dp9ik){
		static char info[] = "Plan 9 session secret";
		ai->nsecret = 256;
		ai->secret = mallocz(ai->nsecret, 1);
		hkdf_x(	crand, 2*NONCELEN,
			(uchar*)info, sizeof(info)-1,
			(uchar*)t.key, NONCELEN,
			ai->secret, ai->nsecret,
			hmac_sha2_256, SHA2_256dlen);
	} else {
		ai->nsecret = 8;
		ai->secret = mallocz(ai->nsecret, 1);
		des56to64((uchar*)t.key, ai->secret);
	}

	memset(&t, 0, sizeof(t));
	memset(&auth, 0, sizeof(auth));
	memset(&authkey, 0, sizeof(authkey));
	memset(cchal, 0, sizeof(cchal));
	memset(crand, 0, sizeof(crand));
	free(proto);

	return ai;
}

static int
getkey(Authkey *key, char *user, char *dom, char *proto, char *pass)
{
	if(pass != nil && *pass)
		pass = estrdup(pass);
	else {
		sysfatal("getkey: no password");
	}
	if(pass != nil){
		memset(key, 0, sizeof(*key));
		passtokey(key, pass);
		if(strcmp(proto, "dp9ik") == 0) {
			authpak_hash(key, user);
		}
		return 1;
	}
	return 0;
}
