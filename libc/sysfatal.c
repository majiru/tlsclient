#include <u.h>
#include <libc.h>

#include <stdlib.h>

static void
_sysfatalimpl(char *fmt, va_list arg)
{
	vfprint(2, fmt, arg);
	fprint(2, "\n");
	exit(1);
}

void (*_sysfatal)(char *fmt, va_list arg) = _sysfatalimpl;

void
sysfatal(char *fmt, ...)
{
	va_list arg;

	va_start(arg, fmt);
	(*_sysfatal)(fmt, arg);
	va_end(arg);
}
