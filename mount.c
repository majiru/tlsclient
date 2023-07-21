#ifdef __linux__
#define _GNU_SOURCE
#endif

#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <err.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define nelem(x) (sizeof x / sizeof x[0])

enum {
	OPT_MAX = 4108,
	PATH_MAX = 4096,
};

static char *mountargv[256];
static int mountargc = 0;

static char *optargv[256];
static int optargc = 0;

static char *port = NULL;
static char *user = NULL;
static char *authbox = NULL;
static char *askpass = "/usr/bin/env systemd-ask-password";

static void
appendarg(char *s)
{
	if(mountargc >= nelem(mountargv)-1)
		errx(EINVAL, "argument overflow");
	mountargv[mountargc++] = strdup(s);
	mountargv[mountargc] = NULL;
}

static void
_appendopt(char *key, char *val)
{
	char buf[OPT_MAX];

	if(optargc >= nelem(optargv)-1)
		errx(EINVAL, "option overflow");
	if(val == NULL)
		snprintf(buf, sizeof buf, "%s%s", optargc == 0 ? "" : ",", key);
	else
		snprintf(buf, sizeof buf, "%s%s=%s", optargc == 0 ? "" : ",", key, val);
	optargv[optargc++] = strdup(buf);
	optargv[optargc] = NULL;
}

static void
appendopt(char *key, char *val)
{
	if(strcmp(key, "port") == 0){
		port = strdup(val);
		return;
	} else if(strcmp(key, "auth") == 0){
		authbox = strdup(val);
		return;
	} else if(strcmp(key, "askpass") == 0){
		askpass = strdup(val);
		return;
	} else if(strcmp(key, "user") == 0){
		user = strdup(val);
		/* passthrough as well */
	} else if(strcmp(key, "trans") == 0){
		errx(EINVAL, "trans=fd is set by 9ptls and can not be overriden");
	} else if(strcmp(key, "rfdno") == 0 || strcmp(key, "wfdno") == 0){
		errx(EINVAL, "rfdno and wfdno are reserved by 9ptls and can not be overriden");
	}
	_appendopt(key, val);
}

static void
parseoptions(char *opt)
{
	char *s;
	char *key, *val;
	int inquote;

	key = val = NULL;
	inquote = 0;
	for(s = opt; *s != '\0'; s++){
		if(key == NULL)
			key = s;
		if(*s == '"'){
			inquote = !inquote;
			continue;
		}
		if(inquote)
			continue;
		switch(*s){
		case '=':
			if(key == s)
				errx(EINVAL, "option argument has no key, only a value");
			*s = '\0';
			if(s[1] == '\0')
				errx(EINVAL, "key %s has no value", key);
			val = s+1;
			continue;
		case ',':
			if(key == s)
				errx(EINVAL, "extra comma");
			*s = '\0';
			appendopt(key, val);
			key = val = NULL;
			continue;
		}
	}
	if(inquote)
		errx(EINVAL, "unterminated double quote");
	if(key != NULL)
		appendopt(key, val);

	_appendopt("trans", "fd");
	_appendopt("rfdno", "0");
	_appendopt("wfdno", "1");
}

static void
flattenoptions(char *opt, int n)
{
	char *s, *e;
	int i, j;

	s = opt;
	e = opt + n - 2;

	for(i = 0; i < optargc; i++){
		j = strlen(optargv[i]);
		if(s+j >= e)
			n = e-s;
		memcpy(s, optargv[i], j);
		s[j] = '\0';
		s += j;
	}
}

void
usage(void)
{
	errx(EINVAL, "Usage: mount.9ptls [-sfnvh] [-o options] [-N namespace] <host> <mountpoint>");
}

int
main(int argc, char **argv)
{
	int c;
	int sflag, fflag, nflag, vflag;
	char options[OPT_MAX];
	char namespace[PATH_MAX];

	sflag = fflag = nflag = vflag = 0;
	options[0] = namespace[0] = '\0';

	while((c = getopt_long(argc, argv, "sfnvo:N:h?", 0, 0)) != -1){
		switch(c){
		case 's':
			sflag = 1;
			break;
		case 'f':
			fflag = 1;
			break;
		case 'n':
			nflag = 1;
			break;
		case 'v':
			vflag = 1;
			break;
		case 'o':
			snprintf(options, sizeof options, "%s", optarg);
			break;
		case 'N':
			snprintf(namespace, sizeof namespace, "%s", optarg);
			break;
		case '?': case 'h':
			if(optopt)
				errx(EINVAL, "invalid option '%c'", optopt);
			usage();
			break;
		}
	}

	argc -= optind;
	argv += optind;

	if(argc != 2)
		usage();

	parseoptions(options);
	if(port == NULL)
		errx(EINVAL, "a port option must be given");
	if(user == NULL && (user = getenv("USER")) == NULL)
		errx(EINVAL, "user option not given and count not infer");
	setenv("TLSCLIENT_ASKPASS", askpass, 1);
	flattenoptions(options, sizeof options);

	appendarg("tlsclient");
	appendarg("-b");
	appendarg("-h");
	appendarg(argv[0]);
	if(authbox != NULL){
		appendarg("-a");
		appendarg(authbox);
	}
	appendarg("-u");
	appendarg(user);
	appendarg("-p");
	appendarg(port);

	appendarg("mount");
	if(sflag)
		appendarg("-s");
	if(fflag)
		appendarg("-f");
	if(nflag)
		appendarg("-n");
	if(vflag)
		appendarg("-v");
	if(namespace[0] != '\0'){
		appendarg("-N");
		appendarg(namespace);
	}
	appendarg("-i");
	appendarg("-t");
	appendarg("9p");
	appendarg("-o");
	appendarg(options);
	appendarg(argv[0]);
	appendarg(argv[1]);

	execvp("tlsclient", mountargv);
	err(EXIT_FAILURE, "could not exec");
}
