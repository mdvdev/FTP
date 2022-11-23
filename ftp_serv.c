#include <stdarg.h>
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <unistd.h>
#include <fcntl.h>
#include <syslog.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <time.h>
#include "aux_func.h"

#define PORT_OPEN	 		"125 Port %d open.\r\n"
#define INPUT_CORRECT_CONT	"200 Input correct, continue.\r\n"
#define CORRECT_REG	 		"201 Account successfully registered.\r\n"
#define UNKNOWN_CMD	 		"202 Unknown command.\r\n"
#define ACCT_NAME	 		"203 Account name is %s.\r\n"
#define FILE_SIZE	 		"204 File size: %lld Kbytes.\r\n"
#define MOD_TIME			"205 Modification time: %s.\r\n"
#define SUCC_RENAME			"206 File renamed successfully.\r\n"
#define SUCC_DEL			"207 File deleted successfully.\r\n"
#define INPUT_CORRECT 		"212 Input correct.\r\n"
#define WELCOME_MSG	 		"220 Welcome to FTP-server! HELP for more info.\r\n"
#define SUCC_QUIT	 		"221 Successful completion on QUIT command. Bye.\r\n"
#define CORRECT_AUTH 		"230 Authentication was successful.\r\n"
#define ANON_USER	 		"330 Anonymous login successful.\r\n"
#define NEED_PASS	 		"331 Username is correct, need password.\r\n"
#define INSUF_RIGHTS		"425 Insufficient access rights.\r\n"
#define INCORRECT_PASS		"451 Incorrect password.\r\n"
#define TOO_LONG_INPUT		"500 Input too long.\r\n"
#define EMPTY_SEC_ARG	 	"501 Empty second argument not allowed.\r\n"
#define INVALID_PASS	 	"502 Incorrect password. Use only latin and/or numbers. Max len: %d.\r\n"
#define BAD_CMD_SEQUENCE 	"503 Bad sequence of commands.\r\n"
#define RETR_ERROR			"503 Error in retrieving the file.\r\n"
#define STOR_ERROR			"504 Error in storing the file.\r\n"
#define DATA_SOCK_ERROR		"506 Cannot accept connection on data socket.\r\n"
#define OP_FILE_ERROR		"507 Cannot open file.\r\n"
#define READ_DIR_ERROR		"508 Error while reading from directory.\r\n"
#define INVALID_REG_NAME 	"530 Invalid username.\r\n"
#define USER_EXIST	 		"531 User already exist.\r\n"
#define USER_NOT_EXIST	 	"532 User doesn't exist.\r\n"
#define LIMIT_EXCEEDED	 	"533 Password attempt limit exceeded.\r\n"
#define FILE_EXIST			"534 File already exist.\r\n"
#define FILE_NOT_EXIST	 	"553 File does not exist.\r\n"

#define MIN_PORT	 	  1024
#define MAX_PORT 		 65535
#define QLEN		   	    32
#define MAX_NAME_LEN   	    16
#define MAX_PASS_LEN   	    32
#define MAX_PERMS_LEN  	 	 6
#define MAX_PASS_ENTR 		 3
#define FILE_NAME_SZ  	   255
#define FILES_TRANS_AT_ONCE	20 

#define CMD_SOCK_READY \
	(FD_ISSET(sess->cmd_fd, readfds))
#define LISTEN_DSOCK_READY \
	((sess->ls_data_fd != -1) && FD_ISSET(sess->ls_data_fd, readfds))
#define SF_WRITE_READY \
	((sess->state != get_file) && FD_ISSET(sess->data_fd, writefds))
#define GF_READ_READY \
	((sess->state == get_file) && FD_ISSET(sess->data_fd, readfds))
#define SOCK_REUSE(fd)  							\
	{ 												\
		int opt = 1;								\
		setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, 	\
			&opt, sizeof(opt)); 					\
	} 
#define ERROR_HANDL(sess)							\
	{ 												\
		struct session *tmp = sess; 				\
		sess = sess->next; 							\
		sess_close_connect(tmp); 					\
		continue; 									\
	} 
	
typedef unsigned short int uint16_t;
typedef unsigned int uint32_t;

typedef enum {
	start,
	main_st,
	send_file,
	get_file,
	help,
	reg_passwd,
	log_passwd,
	rename_file,
	list_dir,
	end,
	error
} fst_state;

typedef enum {
	anon,
	user,
	editor,
	root
} user_perms;

typedef enum {
	upload_file,
	download_file,
	del_file,
	ren_file
} access_opt;

struct session {
	char 			cmd_buf[BUFSIZE];
	char 			*uname;
	char			*saved_uname;
	char			*saved_ren_fname;
	char			*fname;
	DIR				*dir;
	struct session 	*next;
	int 			cmd_buf_used;
	int				cmd_fd;
	int				data_fd;
	int				ls_data_fd;
	int				fd;
	fst_state 		state;
	user_perms 		uperms;
	int 			pass_entr_num;
	uint32_t 		ip;
	uint16_t 		port;
};

static struct session *first_elem = NULL;
static struct session *last_elem = NULL;

static const char *accounts_file = ".accounts";
static const char *commands_file = ".commands";

static void
daemonization(const char *log_print, const char *cwd)
{
	if (chdir(cwd) == -1) {
		perror("chdir");
		exit(1);
	}

	close(0);
	close(1);
	close(2);

	open("/dev/null", O_RDONLY);
	open("/dev/null", O_WRONLY);
	open("/dev/null", O_WRONLY);

	if (fork() > 0)
		exit(0);
	setsid();
	if (fork() > 0)
		exit(0);
	openlog(log_print, LOG_USER, 0);
}

static void
sess_send_msg(struct session *sess, const char *fmt, ...)
{
	va_list ap;
	char *msg;
	int str_len;

	va_start(ap, fmt);
	str_len = vsnprintf(NULL, 0, fmt, ap);
	va_end(ap);

	va_start(ap, fmt);
	msg = malloc(str_len+1);
	vsnprintf(msg, str_len+1, fmt, ap);

	if (write(sess->cmd_fd, msg, strlen(msg)) == -1)
		sess->state = error;
	
	free(msg);
	va_end(ap);
}

static void
sess_create_acc(struct session *sess, const char *pass)
{
	FILE *fp = fopen(accounts_file, "a");

	if (!fp) {
		syslog(LOG_ERR, "[%s]: %s\n", accounts_file, strerror(errno));
		sess->state = error;
		return;
	}
	fprintf(fp, "%s:%s:%s\n", sess->saved_uname, pass, "user");
	fflush(fp);
	if (ferror(fp)) {
		syslog(LOG_ERR, "[%s]: %s\n", accounts_file, strerror(errno));
		sess->state = error;
	}
	fclose(fp);
}

static user_perms
str_to_perms(const char *perms)
{
	if (STR_EQUAL(perms, "root"))
		return root;
	else if (STR_EQUAL(perms, "editor"))
		return editor;
	else if (STR_EQUAL(perms, "user"))
		return user;
	else 
		return anon;
}

static char *
truncate_fname(const char *fname)
{
	const char *pos;
	char *new_fname;
	int fname_len = strlen(fname);

	for (pos = fname+fname_len-1; pos != fname && *pos != '/'; --pos)
		;
	new_fname = malloc(fname + fname_len - pos + 1);
	memcpy(new_fname, pos == fname ? fname : pos + 1, 
		fname + fname_len - pos + 1);
	return new_fname;
}

static inline const char *
perms_to_str(user_perms uperms)
{
	switch (uperms) {
	case root:
		return "root";
	case editor:
		return "editor";
	case user:
		return "user";
	case anon:
		return "anon";
	default:
		return NULL;
	}
}

static int
sess_usr_exist(struct session *sess, const char *uname)
{
	FILE *fp = fopen(accounts_file, "r");
	char *name_attr; 
	char buf[BUFSIZE];

	while (fgets(buf, BUFSIZE, fp)) {
		name_attr = strtok(buf, ":");
		if (STR_EQUAL(uname, name_attr)) {
			fclose(fp);
			return 1;
		}
	}
	fclose(fp);

	return 0;
}

static int
is_valid_input(const char *uname, int input_size)
{
	int i;

	for (i = 0; uname[i] && i < input_size; ++i) 
		if (!isalnum(uname[i]))
			return 0;

	return i < input_size;
}

static void
sess_create_aux_file(struct session *sess)
{
	char *aux_fname = concat_str(".", sess->fname);
	FILE *fp = fopen(aux_fname, "w");
	const char *perms = perms_to_str(sess->uperms);

	fprintf(fp, "%s:%s\n", sess->uname, perms);
	fclose(fp);
	free(aux_fname);
}

static int
sess_is_valid_access(struct session *sess, const char *fname, access_opt a_opt)
{
	char buf[BUFSIZE];
	char *aux_fname = concat_str(".", fname);
	char *perms, *owner_name;
	FILE *fp = fopen(aux_fname, "r");

	fgets(buf, BUFSIZE, fp);
	owner_name = strtok(buf, ":");
	perms = strtok(NULL, "\n");

	fclose(fp);
	free(aux_fname);

	if (STR_EQUAL(sess->uname, owner_name) || sess->uperms == root)
		return 1;
	if (a_opt == del_file)
		return 0;
	return sess->uperms >= str_to_perms(perms);
}

static char *
sess_get_pass(struct session *sess)
{
	char buf[BUFSIZE];
	static char pass[MAX_PASS_LEN+1];
	FILE *fp = fopen(accounts_file, "r");

	while (fgets(buf, BUFSIZE, fp)) {
		char *uname = strtok(buf, ":");
		if (STR_EQUAL(uname, sess->saved_uname)) {
			strncpy(pass, strtok(NULL, ":"), MAX_PASS_LEN+1);
			break;
		}
	}
	fclose(fp);
	return pass;
}

static int
sess_create_ft_sock(struct session *sess, int *out_port)
{
	int ft_fd, port;
	struct sockaddr_in saddr;
	socklen_t slen = sizeof(saddr);
	
	srand(time(NULL));
	
	ft_fd = socket(AF_INET, SOCK_STREAM, 0);
	saddr.sin_addr.s_addr = htonl(INADDR_ANY);
	saddr.sin_family = AF_INET;

	do {
		port = (rand() % (MAX_PORT-MIN_PORT+1)) + MIN_PORT;   
		saddr.sin_port = htons(port);
	} while (bind(ft_fd, (struct sockaddr *) &saddr, slen) == -1);

	*out_port = port;
	return ft_fd;
}

static inline void
sess_create_data_sock(struct session *sess)
{
	int port;

	sess->ls_data_fd = sess_create_ft_sock(sess, &port); 
	listen(sess->ls_data_fd, QLEN); 						
	sess_send_msg(sess, PORT_OPEN, port);
}

static void
sess_list_dir(struct session *sess)
{
	struct dirent *dent;
	struct dyn_array {
		char *begin;
		char *pos;
		int size;
	} msg = { 
		.begin = malloc(BUFSIZE),
		.pos = msg.begin,
		.size = BUFSIZE
	};
	int saved_errno = errno;
	int i = 0;

	while (i < FILES_TRANS_AT_ONCE && (dent = readdir(sess->dir)) != NULL) {
		int fname_len = strlen(dent->d_name);
		/* skip auxiliary files with currect 
			and parent directories */
		if (*dent->d_name == '.')
			continue;
		/* not enough space in buffer */
		if (msg.pos+fname_len+1 >= msg.begin+msg.size) {
			int buf_used = msg.pos - msg.begin;
			/* increase the size by the missing number
		    	of bytes */
			msg.size += (msg.pos+fname_len+1 - (msg.begin+msg.size));
			/* for later use */
			msg.size *= 2;
			msg.begin = realloc(msg.begin, msg.size);
			msg.pos = msg.begin+buf_used;
		}
		sprintf(msg.pos, "%s\n", dent->d_name);
		msg.pos += (fname_len+1);
		i++;
	}

	if (msg.pos != msg.begin)
		write(sess->data_fd, msg.begin, msg.pos-msg.begin);
	if (errno != saved_errno) {
		sess->state = error;
		goto end;
	}
	if (dent == NULL) {
		closedir(sess->dir);
		sess->dir = NULL;
		sess->state = end;
	}
end:
	free(msg.begin);
}

static void
sess_change_perms(struct session *sess)
{
	char buf[BUFSIZE];
	FILE *fp = fopen(accounts_file, "r");

	while (fgets(buf, BUFSIZE, fp)) {
		char *uname = strtok(buf, ":");
		if (STR_EQUAL(uname, sess->saved_uname)) {
			/* skip password */
			strtok(NULL, ":");
			sess->uperms = str_to_perms(strtok(NULL, "\n"));
			break;
		}
	}
	fclose(fp);
}

static void
REGS_handl(struct session *sess, const char *arg)
{
	if (arg == NULL) {
		sess_send_msg(sess, EMPTY_SEC_ARG);
		return;
	}
	if (sess_usr_exist(sess, arg)) {
		sess_send_msg(sess, USER_EXIST);
		return;
	}
	sess_send_msg(sess, INPUT_CORRECT_CONT);
	sess->saved_uname = strdup(arg);
	sess->state = reg_passwd;
}

static void
PASS_handl(struct session *sess, const char *arg)
{
	if (arg == NULL) {
		sess_send_msg(sess, EMPTY_SEC_ARG);
		return;
	}
	if (sess->state == reg_passwd) {
		if (!is_valid_input(arg, MAX_PASS_LEN)) {
			sess_send_msg(sess, INVALID_PASS, MAX_PASS_LEN);
			return;
		}
		sess_create_acc(sess, arg);
		sess_send_msg(sess, CORRECT_REG);
		free(sess->saved_uname);
		sess->state = main_st;
	} else if (sess->state == log_passwd) {
		/* function return pointer to static array */
		char *pass = sess_get_pass(sess);
		if (!STR_EQUAL(arg, pass)) {
			(sess->pass_entr_num)++;
			if (sess->pass_entr_num == MAX_PASS_ENTR) {
				sess_send_msg(sess, LIMIT_EXCEEDED);
				free(sess->saved_uname);
				sess->state = end;
				return;
			} else {
				sess_send_msg(sess, INCORRECT_PASS);
				return;
			}
		} else  {
			sess_send_msg(sess, CORRECT_AUTH);
			sess->uname = sess->saved_uname;
			sess_change_perms(sess);
			sess->state = main_st;
		}
	} else
		sess_send_msg(sess, BAD_CMD_SEQUENCE);
}

static void
USER_handl(struct session *sess, const char *arg)
{
	if (arg == NULL) {
		sess_send_msg(sess, EMPTY_SEC_ARG);
		return;
	}
	if (STR_EQUAL(arg, "anonymous")) 
		sess_send_msg(sess, ANON_USER);
	else
		if (!sess_usr_exist(sess, arg)) {
			sess_send_msg(sess, USER_NOT_EXIST);
			return;
		} else {
			sess_send_msg(sess, NEED_PASS);
			sess->saved_uname = strdup(arg);
			sess->state = log_passwd;
		}
}	

static inline void
LIST_handl(struct session *sess)
{
	sess->state = list_dir;
	sess_create_data_sock(sess);
}

static inline void
ACCT_handl(struct session *sess)
{
	sess_send_msg(sess, ACCT_NAME, sess->uname);
}

static void
RETR_handl(struct session *sess, const char *arg)
{
	int res;

	if (arg == NULL) {
		sess_send_msg(sess, EMPTY_SEC_ARG);
		return;
	}
	res = is_file_exist(arg);
	if (res == 0) {
		sess_send_msg(sess, FILE_NOT_EXIST);
		return;
	} else if (res == -1) {
		sess_send_msg(sess, READ_DIR_ERROR);
		sess->state = error;
		return;
	}
	if (!sess_is_valid_access(sess, arg, download_file)) {
		sess_send_msg(sess, INSUF_RIGHTS);
		return;
	}
	sess->fname = strdup(arg);
	sess->state = send_file;
	sess_create_data_sock(sess);
}

static inline void
UNKN_handl(struct session *sess)
{
	sess_send_msg(sess, UNKNOWN_CMD);
}

static void
DESC_handl(struct session *sess, const char *arg)
{
	if (arg == NULL) {
		sess_send_msg(sess, EMPTY_SEC_ARG);
		return;
	}
	sess->fname = concat_str(".", arg);
	sess->state = send_file;
	sess_send_msg(sess, INPUT_CORRECT);
	sess_create_data_sock(sess);
}

static inline void
QUIT_handl(struct session *sess)
{
	sess->state = end;
	sess_send_msg(sess, SUCC_QUIT);
}

static void
SIZE_handl(struct session *sess, const char *arg)
{
	struct stat st;

	if (stat(arg, &st) == -1) {
		sess_send_msg(sess, FILE_NOT_EXIST);
		return;
	}
	sess_send_msg(sess, FILE_SIZE, st.st_size/1024);
}

static void
MDTM_handl(struct session *sess, const char *arg)
{
	struct stat st;
	struct tm *time;
	char *atime;

	if (arg == NULL) {
		sess_send_msg(sess, EMPTY_SEC_ARG);
		return;
	}
	if (stat(arg, &st) == -1) {
		sess_send_msg(sess, FILE_NOT_EXIST);
		return;
	}
	time = localtime(&st.st_mtimespec.tv_sec);
	atime = asctime(time);
	atime[strlen(atime)-1] = '\0';
	sess_send_msg(sess, MOD_TIME, atime);
}

static void
STOR_handl(struct session *sess, const char *arg)
{
	int res;
	char *new_fname;

	if (arg == NULL) {
		sess_send_msg(sess, EMPTY_SEC_ARG);
		return;
	}
	/* anonymous can't upload files */
	if (sess->uperms == anon) {
		sess_send_msg(sess, INSUF_RIGHTS);
		return;
	}
	new_fname = truncate_fname(arg);
	res = is_file_exist(new_fname);
	if (res == 1) {
		sess_send_msg(sess, FILE_EXIST);
		return;
	} else if (res == -1) {
		sess_send_msg(sess, READ_DIR_ERROR);
		sess->state = error;
		return;
	}
	sess->fname = new_fname;
	sess->state = get_file;
	sess_create_data_sock(sess);
}

static inline void
HELP_handl(struct session *sess)
{
	sess->fname = strdup(commands_file);
	sess->state = help;
	sess_create_data_sock(sess);
}

static void
DELE_handl(struct session *sess, const char *arg)
{
	char *aux_fname;

	if (arg == NULL) {
		sess_send_msg(sess, EMPTY_SEC_ARG);
		return;
	}
	if (!sess_is_valid_access(sess, arg, del_file)) {
		sess_send_msg(sess, INSUF_RIGHTS);
		return;
	}
	if (unlink(arg) == -1) {
		sess_send_msg(sess, FILE_NOT_EXIST);
		return;
	}
	aux_fname = concat_str(".", arg);
	unlink(aux_fname);
	free(aux_fname);
	sess_send_msg(sess, SUCC_DEL);
}

static void
RNFR_handl(struct session *sess, const char *arg)
{
	int res;
	
	if (arg == NULL) {
		sess_send_msg(sess, EMPTY_SEC_ARG);
		return;
	}
	res = is_file_exist(arg);
	if (res == 0) {
		sess_send_msg(sess, FILE_NOT_EXIST);
		return;
	} else if (res == -1) {
		sess_send_msg(sess, READ_DIR_ERROR);
		sess->state = error;
		return;
	}
	if (!sess_is_valid_access(sess, arg, ren_file)) {
		sess_send_msg(sess, INSUF_RIGHTS);
		return;
	}
	sess->saved_ren_fname = strdup(arg);
	sess->state = rename_file;
	sess_send_msg(sess, INPUT_CORRECT_CONT);
}

static void
RNTO_handl(struct session *sess, const char *arg)
{
	char *old_aux_fname, *new_aux_fname;
	int res;

	if (arg == NULL) {
		sess_send_msg(sess, EMPTY_SEC_ARG);
		return;
	}
	if (sess->state != rename_file) {
		sess_send_msg(sess, BAD_CMD_SEQUENCE);
		return;
	}
	res = is_file_exist(arg);
	if (res == 1) {
		sess_send_msg(sess, FILE_EXIST);
		return;
	} else if (res == -1) {
		sess_send_msg(sess, READ_DIR_ERROR);
		sess->state = error;
		return;
	}
	rename(sess->saved_ren_fname, arg);
	old_aux_fname = concat_str(".", sess->saved_ren_fname);
	new_aux_fname = concat_str(".", arg);
	rename(old_aux_fname, new_aux_fname);

	sess->state = main_st;
	free(sess->saved_ren_fname);
	free(old_aux_fname);
	free(new_aux_fname);
	sess_send_msg(sess, SUCC_RENAME);
}

static void
sess_cmd_handl(struct session *sess, char *cmd)
{
	char *first_word, *second_word;

	first_word = strtok(cmd, " \t\n");
	/* empty string */
	if (first_word == NULL)
		return;
	second_word = strtok(NULL, " \t\n");

	if (STR_EQUAL(first_word, "REGS"))
		REGS_handl(sess, second_word);
	else if (STR_EQUAL(first_word, "PASS"))
		PASS_handl(sess, second_word);
	else if (STR_EQUAL(first_word, "USER"))
		USER_handl(sess, second_word);
	else if (STR_EQUAL(first_word, "LIST"))
		LIST_handl(sess);
	else if (STR_EQUAL(first_word, "HELP"))
		HELP_handl(sess);
	else if (STR_EQUAL(first_word, "ACCT"))
		ACCT_handl(sess);
	else if (STR_EQUAL(first_word, "RETR"))
		RETR_handl(sess, second_word);
	else if (STR_EQUAL(first_word, "DESC"))
		DESC_handl(sess, second_word);
	else if (STR_EQUAL(first_word, "QUIT"))
		QUIT_handl(sess);
	else if (STR_EQUAL(first_word, "SIZE"))
		SIZE_handl(sess, second_word);
	else if (STR_EQUAL(first_word, "MDTM"))
		MDTM_handl(sess, second_word);
	else if (STR_EQUAL(first_word, "STOR"))
		STOR_handl(sess, second_word);
	else if (STR_EQUAL(first_word, "DELE"))
		DELE_handl(sess, second_word);
	else if (STR_EQUAL(first_word, "RNFR"))
		RNFR_handl(sess, second_word);
	else if (STR_EQUAL(first_word, "RNTO"))
		RNTO_handl(sess, second_word);
	else
		UNKN_handl(sess);
}

static void
sess_fsm_step(struct session *sess, char *cmd)
{
	int res;

	switch (sess->state) {
	case start:
		sess_send_msg(sess, WELCOME_MSG);
		sess->state = main_st;
		break;
	case main_st:
	case log_passwd:
	case reg_passwd:
	case rename_file:
		sess_cmd_handl(sess, cmd);
		break;
	case send_file:
	case help:
	 	/* send data from fd (file) to data socket (data_fd) */
		res = transf_data(sess->data_fd, sess->fd);
		/* EOF on sess->fd */
		if (res == 0)
			sess->state = end;
		else if (res == -1)
			sess->state = error;
		break;
	case get_file:
	 	/* send data from data_fd to fd */
		res = transf_data(sess->fd, sess->data_fd);
		/* EOF on sess->fd */
		if (res == 0)
			sess->state = end;
		else if (res == -1)
			sess->state = error;
		break;
	case list_dir:
		sess_list_dir(sess);
		break;
	case error:
	case end:
		break;
	}
}

static void
sess_read(struct session *sess)
{
	int rc, bufp = sess->cmd_buf_used;
	const char *lf_pos;

	rc = read(sess->cmd_fd, sess->cmd_buf+bufp, BUFSIZE-bufp);
	if (rc <= 0) {
		sess->state = (rc == 0) ? end : error;
		return;
	}
	sess->cmd_buf_used += rc;
	lf_pos = find_lf(sess->cmd_buf, sess->cmd_buf_used);
	if (lf_pos != NULL) {
		int copy = lf_pos - sess->cmd_buf;
		char *cmd = malloc(copy + 1);
		memcpy(cmd, sess->cmd_buf, copy);
		cmd[copy] = '\0';
		sess->cmd_buf_used -= (copy + 1);
		memmove(sess->cmd_buf, lf_pos + 1, sess->cmd_buf_used);
		if (cmd[copy - 1] == '\r')
			cmd[copy - 1] = '\0';

		sess_fsm_step(sess, cmd);
		free(cmd);
		if (sess->cmd_buf_used >= BUFSIZE)
			sess_send_msg(sess, TOO_LONG_INPUT);
	}
}

static struct session *
serv_cladd(struct session *elem, const struct sockaddr_in *claddr, int clfd)
{
	struct session *cl = malloc(sizeof(*cl));

	cl->cmd_fd = clfd;
	cl->data_fd = -1;
	cl->ls_data_fd = -1;
	cl->state = start;
	cl->uperms = anon;
	cl->uname = "Anonymous";
	cl->saved_uname = NULL;
	cl->saved_ren_fname = NULL;
	cl->dir = NULL;
	cl->pass_entr_num = 0;
	cl->port = ntohs(claddr->sin_port);
	cl->ip = ntohl(claddr->sin_addr.s_addr);
	cl->cmd_buf_used = 0;
	cl->fname = NULL;
	cl->fd = -1;
	cl->next = NULL;
	if (elem)
		elem->next = cl;

	return cl;
}

static void
sess_remove(struct session *elem)
{
	struct session *sess;

	if (first_elem == elem) {
		first_elem = elem->next;
		if (last_elem == elem)
			last_elem = elem->next;
		return;
	}
	for (sess = first_elem; sess; sess = sess->next)
		if (sess->next == elem) {
			sess->next = elem->next;
			if (sess->next == NULL)
				last_elem = sess;
			return;
		}
}

static int
serv_fds_init(fd_set *readfds, fd_set *writefds)
{
	const struct session *sess;
	int max_fd = -1;

	for (sess = first_elem; sess != NULL; sess = sess->next) {
		/* is there a request from client to
			create a data socket? */
		if (sess->ls_data_fd != -1) {
			FD_SET(sess->ls_data_fd, readfds);
			if (sess->ls_data_fd > max_fd)
				max_fd = sess->ls_data_fd;
		/* whether created a data socket? */
		} else if (sess->data_fd != -1) {
			if (sess->state != get_file)
				FD_SET(sess->data_fd, writefds);
			else
				FD_SET(sess->data_fd, readfds);
			if (sess->data_fd > max_fd)
				max_fd = sess->data_fd;
		/* trival case: handle commands from client */
		} else {
			FD_SET(sess->cmd_fd, readfds);
			if (sess->cmd_fd > max_fd)
				max_fd = sess->cmd_fd;
		}
	}

	return max_fd;
}	

static void
sess_close_connect(struct session *sess)
{
	close(sess->cmd_fd);
	if (sess->ls_data_fd != -1)
		close(sess->ls_data_fd);
	if (sess->data_fd != -1)
		close(sess->data_fd);
	if (sess->fd != -1)
		close(sess->fd);
	if (sess->uperms != anon)
		free(sess->uname);
	if (sess->fname != NULL)
		free(sess->fname);
	sess_remove(sess);
	free(sess);
}

static struct session *
serv_accept(struct session *elem, int ls)
{
	struct sockaddr_in claddr;
	socklen_t clsockl = sizeof(claddr);
	int cl_fd = accept(ls, (struct sockaddr *) &claddr, &clsockl);

	if (cl_fd == -1) {
		syslog(LOG_ERR, "%s\n", strerror(errno));
		return NULL;
	}

	return serv_cladd(elem, &claddr, cl_fd);
}

static void
serv_poll(const fd_set *readfds, const fd_set *writefds)
{
	struct session *sess = first_elem;

	while (sess != NULL) {
		if (CMD_SOCK_READY) {
			sess_read(sess);
			if (sess->state == end || sess->state == error) 
				ERROR_HANDL(sess);
		} else if (LISTEN_DSOCK_READY) {
			if (sess->state == send_file || sess->state == help) {
				sess->fd = open(sess->fname, O_RDONLY);
				if (sess->fd == -1) {
					sess_send_msg(sess, OP_FILE_ERROR);
					ERROR_HANDL(sess);
				}
			} else if (sess->state == get_file) {
				sess->fd = open(sess->fname, O_WRONLY | O_CREAT, 0666);
				if (sess->fd == -1) {
					sess_send_msg(sess, OP_FILE_ERROR);
					ERROR_HANDL(sess);
				}
				sess_create_aux_file(sess);
			} else
				sess->dir = opendir(".");

			sess->data_fd = accept(sess->ls_data_fd, NULL, NULL);
			if (sess->data_fd == -1) {
				sess_send_msg(sess, DATA_SOCK_ERROR);
				if (sess->state == get_file) {
					char *aux_fname = concat_str(".", sess->fname);	
					/* remove main and auxiliary files */
					unlink(aux_fname);
					unlink(sess->fname);
					free(aux_fname);
				} else {
					closedir(sess->dir);
					sess->dir = NULL;
				}
				ERROR_HANDL(sess);
			}

			close(sess->ls_data_fd);
			sess->ls_data_fd = -1;
			if (sess->state != list_dir) {
				free(sess->fname);
				sess->fname = NULL;
			}
		} else if (sess->data_fd != -1)
			if (SF_WRITE_READY || GF_READ_READY) {
				sess_fsm_step(sess, NULL);
				if (sess->state == error)
					ERROR_HANDL(sess);
				if (sess->state == end) {
					close(sess->data_fd);
					close(sess->fd);
					sess->data_fd = sess->fd = -1;
					sess->state = main_st;
				}
			}
		sess = sess->next;
	}
}			

static int
serv_go(int ls)
{
	int res;
	int fd, max_fd;
	fd_set rfds, wfds;

	for (;;) {
		FD_ZERO(&rfds);
		FD_ZERO(&wfds);
		FD_SET(ls, &rfds);

		max_fd = ls;

		fd = serv_fds_init(&rfds, &wfds);
		if (fd > max_fd)
			max_fd = fd;

		res = select(max_fd+1, &rfds, &wfds, NULL, NULL);
		if (res == -1) {
			syslog(LOG_ERR, "%s\n", strerror(errno));
			return 2;
		}

		if (FD_ISSET(ls, &rfds)) {
			last_elem = serv_accept(last_elem, ls);
			if (last_elem == NULL)
				return 2;

			/* list is empty? */
			if (first_elem == NULL)
				first_elem = last_elem;

			/* start session */
			sess_fsm_step(last_elem, NULL);
			if (last_elem->state == error)
				sess_close_connect(last_elem);
		}
		serv_poll(&rfds, &wfds);
	}
}

static int
serv_create_lsock(uint16_t port)
{
	struct sockaddr_in lsaddr;
	int ls = socket(AF_INET, SOCK_STREAM, 0);

	if (ls == -1) {
		syslog(LOG_ERR, "%s\n", strerror(errno));
		return -1;
	}
	lsaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	lsaddr.sin_port = htons(port);
	lsaddr.sin_family = AF_INET;
	if (bind(ls, (struct sockaddr *) &lsaddr, sizeof(lsaddr)) == -1) {
		syslog(LOG_ERR, "%s\n", strerror(errno));
		return -1;
	}
	if (ls != -1)
		listen(ls, QLEN);

	return ls;
}

static void
serv_init(uint16_t port)
{
	int ls_fd;

	ls_fd = serv_create_lsock(port);
	if (ls_fd == -1)
		exit(1);
	SOCK_REUSE(ls_fd);
	serv_go(ls_fd);
}	

int	
main(int argc, char **argv)
{
	long port;
	char *err;

	if (argc != 3) {
		fprintf(stderr, "Usage: %s <port> <work_dir>\n", *argv);
		return 1;
	}
	port = strtoul(argv[1], &err, 10);
	if (*err || port > MAX_PORT) {
		fprintf(stderr, "Invalid server port number.\n");
		return 1;
	}

#ifdef DEBUG_NOT_DAEMON
	chdir(argv[2]);
#else
	daemonization(*argv, argv[2]);
#endif

	serv_init(port);

	return 0;
}