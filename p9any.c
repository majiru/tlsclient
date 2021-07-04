#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>

#include <u.h>
#include <args.h>
#include <libc.h>
#include <auth.h>
#include <authsrv.h>
#include <libsec.h>

#include "fncs.h"

void errstr(char *s){}

char*
estrdup(char *s)
{
	s = strdup(s);
	if(s == nil)
		sysfatal("out of memory");
	return s;
}

int
unix_dial(char *host, char *port)
{
	int fd;
	struct sockaddr_in server;
	struct hostent *he;
	struct in_addr **addr_list;

	he = gethostbyname(host);
	if(he == nil){
		printf("could not resolve %s", host);
		return -1;
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

static int
getkey(Authkey *key, char *user, char *dom, char *proto, char *pass)
{
	if(pass != nil && *pass)
		pass = estrdup(pass);
	else {
		printf("getkey: no password");
		return 0;
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

AuthInfo*
p9any(char *user, char *pass, int fd)
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

	if(readstr(fd, buf, sizeof buf) < 0){
		printf("cannot read p9any negotiation");
		return nil;
	}
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
		if((dom = strchr(bbuf, '@')) == nil){
			printf("bad p9any domain");
			return nil;
		}
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
	if(proto == nil){
		printf("server did not offer p9sk1 or dp9ik");
		return nil;
	}
	proto = estrdup(proto);
	sprint(buf2, "%s %s", proto, dom);
	if(write(fd, buf2, strlen(buf2)+1) != strlen(buf2)+1){
		printf("cannot write user/domain choice in p9any");
		return nil;
	}
	if(v2){
		if(readstr(fd, buf, sizeof buf) < 0){
			printf("cannot read OK in p9any");
			return nil;
		}
		if(memcmp(buf, "OK\0", 3) != 0){
			printf("did not get OK in p9any: got %s", buf);
			return nil;
		}
	}
	genrandom(crand, 2*NONCELEN);
	genrandom(cchal, CHALLEN);
	if(write(fd, cchal, CHALLEN) != CHALLEN){
		printf("cannot write p9sk1 challenge");
		return nil;
	}

	n = TICKREQLEN;
	if(dp9ik)
		n += PAKYLEN;

	if(readn(fd, trbuf, n) != n || convM2TR(trbuf, TICKREQLEN, &tr) <= 0){
		printf("cannot read ticket request in p9sk1");
		return nil;
	}

again:
	if(!getkey(&authkey, user, tr.authdom, proto, pass)){
		printf("no password");
		return nil;
	}

	strecpy(tr.hostid, tr.hostid+sizeof tr.hostid, user);
	strecpy(tr.uid, tr.uid+sizeof tr.uid, user);

	if(dp9ik){
		memmove(y, trbuf+TICKREQLEN, PAKYLEN);
		n = gettickets(&authkey, &tr, y, tbuf, sizeof(tbuf));
	} else {
		n = gettickets(&authkey, &tr, nil, tbuf, sizeof(tbuf));
	}
	if(n <= 0){
		printf("cannot get auth tickets in p9sk1");
		return nil;
	}

	m = convM2T(tbuf, n, &t, &authkey);
	if(m <= 0 || t.num != AuthTc){
		printf("?password mismatch with auth server\n");
		if(pass != nil && *pass){
			printf("wrong password");
			return nil;
		}
		goto again;
	}
	n -= m;
	memmove(tbuf, tbuf+m, n);

	if(dp9ik && write(fd, y, PAKYLEN) != PAKYLEN){
		printf("cannot send authpak public key back");
		return nil;
	}

	auth.num = AuthAc;
	memmove(auth.rand, crand, NONCELEN);
	memmove(auth.chal, tr.chal, CHALLEN);
	m = convA2M(&auth, tbuf+n, sizeof(tbuf)-n, &t);
	n += m;

	if(write(fd, tbuf, n) != n){
		printf("cannot send ticket and authenticator back");
		return nil;
	}

	if((n=read(fd, tbuf, m)) != m || memcmp(tbuf, "cpu:", 4) == 0){
		if(n <= 4){
			printf("cannot read authenticator");
			return nil;
		}

		/*
		 * didn't send back authenticator:
		 * sent back fatal error message.
		 */
		memmove(buf, tbuf, n);
		i = readn(fd, buf+n, sizeof buf-n-1);
		if(i > 0)
			n += i;
		buf[n] = 0;
		printf("server says: %s", buf);
		return nil;
	}
	
	if(convM2A(tbuf, n, &auth, &t) <= 0
	|| auth.num != AuthAs || tsmemcmp(auth.chal, cchal, CHALLEN) != 0){
		print("?you and auth server agree about password.\n");
		print("?server is confused.\n");
		return nil;
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

