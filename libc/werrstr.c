#include <u.h>
#include <libc.h>

char errbuf[ERRMAX];

int
errstr(char *buf, uint n)
{
	if(n > ERRMAX)
		n = ERRMAX;
	utfecpy(errbuf, errbuf+n, buf);
	return utflen(buf);
}

int
rerrstr(char *buf, uint n)
{
	utfecpy(buf, buf+n, errbuf);
	return utflen(buf);
}

void
werrstr(char *f, ...)
{
	va_list arg;

	va_start(arg, f);
	vsnprint(errbuf, sizeof errbuf, f, arg);
	va_end(arg);
}

