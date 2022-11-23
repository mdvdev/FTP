#include "aux_func.h"

char *
concat_str(const char *s1, const char *s2)
{
	int len_s1 = strlen(s1), len_s2 = strlen(s2);
	char *cat_str = malloc(len_s1 + len_s2 + 1);

	memcpy(cat_str, s1, len_s1);
	memcpy(cat_str + len_s1, s2, len_s2 + 1);
	return cat_str;
}

int 
transf_data(int to_fd, int from_fd)
{
	char buf[BUFSIZE];
	int rc;

#ifdef FTP_SERV
	int i = 0;
#endif
	for (;;) {
#ifdef FTP_SERV
		if (i >= CHUNKS_NUM)
			break;
		i++;
#endif
		rc = read(from_fd, buf, BUFSIZE);
		if (rc == 0 || rc == -1)
			break;
		if (write(to_fd, buf, rc) == -1)
			return -1;
	}
	return rc;
}

int 
is_file_exist(const char *fname)
{
	DIR *dir = opendir(".");
	struct dirent *dent;
	int saved_errno = errno;

	while ((dent = readdir(dir)) != NULL)
		if (STR_EQUAL(fname, dent->d_name))
			return 1;
	return (saved_errno == errno) ? 0 : -1;
}

const char *
find_lf(const char *buf, int size)
{
	const char *pos;	

	for (pos = buf; *pos != '\0'; ++pos)
		if (*pos == '\n')
			return pos;
	return NULL;
}