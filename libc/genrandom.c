#include <u.h>
#include <libc.h>

#undef long
#undef ulong
#include <unistd.h>

void
genrandom(uchar *buf, int nbytes)
{
	getentropy(buf, nbytes);
}
