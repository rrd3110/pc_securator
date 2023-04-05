/* Peter Gutmann's algorithm for secure file-wiping .
Description: Most delete operations do not affect the data but rather they merely deletes 
any underlying metadata that the filesystem associates with the contents of the file. In 
short, to permanently erase the data contents, we need to overwrite it with with non-important 
data before delete is performed. This is a very sophisticated method as it depends on the type 
of storage used. 
*/

#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#define SPC_WIPE_BUFSIZE 4096

static int write_data(int fd, const void *buf, size_t nbytes) {
 size_t towrite, written = 0;
 ssize_t result;

 
do {

 
if (nbytes - written > SSIZE_MAX) towrite = SSIZE_MAX;
 else towrite = nbytes - written;
 if ((result = write(fd, (const char *)buf + written, towrite)) >= 0)
 written += result;
 else if (errno != EINTR) return 0;
 } while (written < nbytes);
 return 1;
}

static int random_pass(int fd, size_t nbytes)
{
 size_t towrite;
 unsigned char buf[SPC_WIPE_BUFSIZE];

 
if (lseek(fd, 0, SEEK_SET) != 0) return -1;
 while (nbytes > 0) {
 towrite = (nbytes > sizeof(buf) ? sizeof(buf) : nbytes);
 spc_rand(buf, towrite);
 if (!write_data(fd, buf, towrite)) return -1;
 nbytes -= towrite;
  
}

 
fsync(fd);
 return 0;
}

static int pattern_pass(int fd, unsigned char *buf, size_t bufsz, size_t filesz) {
 size_t towrite;

 
if (!bufsz || lseek(fd, 0, SEEK_SET) != 0) return -1;
 while (filesz > 0) {
 towrite = (filesz > bufsz ? bufsz : filesz);
 if (!write_data(fd, buf, towrite)) return -1;
 filesz -= towrite;
 }
 fsync(fd);
 return 0;
}

int spc_fd_wipe(int fd) {
 int count, i, pass, patternsz;
 struct stat st;
 unsigned char buf[SPC_WIPE_BUFSIZE], *pattern;

 
static unsigned char single_pats[16] = {
 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff

 
};
 static unsigned char triple_pats[6][3] = {
 { 0x92, 0x49, 0x24 }, { 0x49, 0x24, 0x92 }, { 0x24, 0x92, 0x49 },
 { 0x6d, 0xb6, 0xdb }, { 0xb6, 0xdb, 0x6d }, { 0xdb, 0x6d, 0xb6 }
 };

 
if (fstat(fd, &st) = = -1) return -1;
if (!st.st_size) return 0;
 
for (pass = 0; pass < 4; pass++)
 if (random_pass(fd, st.st_size) = = -1) return -1;

 
memset(buf, single_pats[5], sizeof(buf));
 if (pattern_pass(fd, buf, sizeof(buf), st.st_size) = = -1) return -1;
 memset(buf, single_pats[10], sizeof(buf));
 if (pattern_pass(fd, buf, sizeof(buf), st.st_size) = = -1) return -1;

 
patternsz = sizeof(triple_pats[0]);
 for (pass = 0; pass < 3; pass++) {
 pattern = triple_pats[pass];
 count = sizeof(buf) / patternsz;
 for (i = 0; i < count; i++)
 memcpy(buf + (i * patternsz), pattern, patternsz);
 if (pattern_pass(fd, buf, patternsz * count, st.st_size) = = -1) return -1;
 }

 
for (pass = 0; pass < sizeof(single_pats); pass++) {
 memset(buf, single_pats[pass], sizeof(buf));
  
if (pattern_pass(fd, buf, sizeof(buf), st.st_size) = = -1) return -1;
 }

 
for (pass = 0; pass < sizeof(triple_pats) / patternsz; pass++) {
 pattern = triple_pats[pass];
 count = sizeof(buf) / patternsz;
 for (i = 0; i < count; i++)
 memcpy(buf + (i * patternsz), pattern, patternsz);
 if (pattern_pass(fd, buf, patternsz * count, st.st_size) = = -1) return -1;
 }

 
for (pass = 0; pass < 4; pass++)
 if (random_pass(fd, st.st_size) = = -1) return -1;
 return 0;
}

int spc_file_wipe(FILE *f) {
 return spc_fd_wipe(fileno(f));
}
