#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "aux_func.h"

#define MAX_PORT 65535
#define RESP_HANDL(res) 							\
	if (res == 0) {									\
		printf("Server closed the connection.\n"); 	\
		exit(0); 									\
	} 												\
	if (res == -1) { 								\
		perror("read"); 							\
		exit(1); 									\
	}

typedef unsigned int uint32_t;
typedef unsigned short uint16_t;

static const char *serv_ip;

static int
serv_connect(const char *ip, uint16_t port)
{
	struct sockaddr_in serv_addr;
	int sfd;
	
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(port);
	serv_addr.sin_addr.s_addr = inet_addr(ip);

	sfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sfd == -1) {
		perror("socket");
		return -1;
	}
	if (connect(sfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) == -1) {
		perror("connect");
		return -1;
	}
	return sfd;
}

static inline void
write_data(int fd, const char *buf, int buf_len)
{
	if (write(fd, buf, buf_len) == -1) {
		perror("write");
		exit(1);
	}
}

static inline char *
create_file_name(const char *fname)
{
	char *s1 = concat_str(getenv("HOME"), "/Downloads/");
	char *s2 = concat_str(s1, fname);
	free(s1);
	return s2;
}

static char *
get_token(const char *str, const char *delim)
{
	static const char *pos;

	if (str != NULL)
		pos = str;

	for (; *pos != '\0'; ++pos) {
		const char *del_pos;
		for (del_pos = delim; *del_pos != '\0'; ++del_pos)
			if (*pos == *del_pos)
				break;
		/* token found? */
		if (*del_pos == '\0') {
			const char *start_pos = pos++;
			char *token;
			for (; *pos != '\0'; ++pos)
				for (del_pos = delim; *del_pos != '\0'; ++del_pos)
					if (*pos == *del_pos)
						goto end;
end:		token = malloc(pos - start_pos + 1);
			memcpy(token, start_pos, pos - start_pos);
			token[pos - start_pos] = '\0';
			return token;
		}
	}
	return NULL;
}

static inline int
get_port(char *str)
{
	strtok(str, " \t\n");
	strtok(NULL, " \t\n");
	return atoi(strtok(NULL, " \t\n"));
}

static void
retr_handl(int sfd)
{
	char buf[BUFSIZE];
	char *fname, *token;
	int data_fd, fd, port, res;
	int rc = read(sfd, buf, BUFSIZE-1);
	
	RESP_HANDL(rc);
	write_data(1, buf, rc);
	/* bad request */
	if (*buf != '1')
		return;
	buf[rc] = '\0';
	port = get_port(buf);
	
	token = get_token(NULL, " \t\n");
	fname = create_file_name(token);
	fd = open(fname, O_WRONLY | O_CREAT | O_TRUNC, 0666);
	if (fd == -1) {
		perror("open");
		exit(1);
	}

	data_fd = serv_connect(serv_ip, port);
	if (data_fd == -1)
		exit(1);
	printf("Client: retrieving file started.\n");
	fflush(stdout);

	res = transf_data(fd, data_fd);
	if (res == -1) {
		perror("there is some error");
		exit(1);
	}

	free(fname);
	free(token);
	close(data_fd);
	close(fd);

	printf("Client: retrieving file completed.\n");
	fflush(stdout);
}

static void
stor_handl(int sfd, const char *msg, int msg_len)
{
	char buf[BUFSIZE];
	char *token = get_token(NULL, " \t\n");
	int data_fd, fd = open(token, O_RDONLY);
	int rc, res, port;

	free(token);
	if (fd == -1) {
		perror("open");
		return;
	}

	write_data(sfd, msg, msg_len);
	/* read response */
	rc = read(sfd, buf, BUFSIZE-1);
	RESP_HANDL(rc);
	write_data(1, buf, rc);
	/* bad request */
	if (*buf != '1') {
		close(fd);
		return;
	}
	buf[rc] = '\0';
	port = get_port(buf);

	data_fd = serv_connect(serv_ip, port);
	if (data_fd == -1)
		exit(1);
	printf("Client: storing file started.\n");
	fflush(stdout);
	
	res = transf_data(data_fd, fd);
	if (res == -1) {
		perror("there is some error");
		exit(1);
	}

	close(data_fd);
	close(fd);

	printf("Client: storing file completed.\n");
	fflush(stdout);
}

static void
help_list_handl(int sfd)
{
	char buf[BUFSIZE];
	int data_fd, port, res;
	int rc = read(sfd, buf, BUFSIZE-1);
	
	RESP_HANDL(rc);
	write_data(1, buf, rc);	
	buf[rc] = '\0';
	port = get_port(buf);

	data_fd = serv_connect(serv_ip, port);
	if (data_fd == -1)
		exit(1);
	/* send data from data socket to fd (file) */
	res = transf_data(1, data_fd);
	if (res == -1) {
		perror("there is some error");
		exit(1);
	}
	close(data_fd);
}

static void
client_go(int sfd)
{
	char buf[BUFSIZE];
	/* server start interaction */
	int rc = read(sfd, buf, BUFSIZE);

	RESP_HANDL(rc);
	write_data(1, buf, rc);

	while ((rc = read(0, buf, BUFSIZE-1)) != 0 && rc != -1) {
		char *cmd;
		if (find_lf(buf, rc) == NULL) {
			printf("Input too big!\n");
			continue;
		}
		buf[rc] = '\0';
		cmd = get_token(buf, " \t\n");
		if (cmd != NULL) {
			if (STR_EQUAL(cmd, "STOR"))	
				stor_handl(sfd, buf, rc);
			else {
				write_data(sfd, buf, rc);
				if (STR_EQUAL(cmd, "RETR"))
					retr_handl(sfd);
				else if (STR_EQUAL(cmd, "HELP") || STR_EQUAL(cmd, "LIST"))
					help_list_handl(sfd);
				else {
			 		rc = read(sfd, buf, BUFSIZE);
					RESP_HANDL(rc);
					write_data(1, buf, rc);
					if (STR_EQUAL(cmd, "QUIT") || STR_EQUAL(strtok(buf, " "), "533")) {
						free(cmd);
						rc = read(sfd, buf, BUFSIZE);
						RESP_HANDL(rc);
					}
				}
			}
		}
		free(cmd);
	}
	if (rc == -1) {
		perror("read");
		exit(1);
	}
}

int
main(int argc, char **argv)
{
	int sfd;
	long port;
	char *err;

	if (argc != 3) {
		fprintf(stderr, "Usage: %s <ip> <port>\n", *argv);
		return 1;
	}
	port = strtoul(argv[2], &err, 10);
	if (*err || port > MAX_PORT) {
		fprintf(stderr, "Invalid server port number.\n");
		return 1;
	}

	serv_ip = argv[1];

	sfd = serv_connect(serv_ip, port);	
	if (sfd == -1) 
		return 1;

	client_go(sfd);

	return 0;
}