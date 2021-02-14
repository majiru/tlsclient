#include <u.h>
#include <libc.h>

#undef long
#undef ulong
#include <sys/random.h>

void
genrandom(uchar *buf, int nbytes)
{
	getrandom(buf, nbytes, 0);
}
