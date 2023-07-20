#include <u.h>
#include <libc.h>

#undef long
#undef ulong
#include <unistd.h>
#ifdef __APPLE__
#include <sys/random.h>
#endif

void
genrandom(uchar *buf, int nbytes)
{
	getentropy(buf, nbytes);
}
