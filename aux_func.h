#ifndef AUX_FUNC_H_SENTRY
#define AUX_FUNC_H_SENTRY

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>

#define BUFSIZE 1024
#define CHUNKS_NUM 3
#define STR_EQUAL(str1, str2) \
	(strcmp((str1), (str2)) == 0)

/* create new string in heap */
char *concat_str(const char *s1, const char *s2);
int transf_data(int to_fd, int from_fd);
int is_file_exist(const char *fname);
const char *find_lf(const char *buf, int size);

#endif