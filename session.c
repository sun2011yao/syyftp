#include "common.h"
#include "session.h"
#include "ftpproto.h"
#include "privparent.h"
#include "privsock.h"
#include "sysutil.h"

void begin_session(session_t *sess)
{
	activate_oobinline(sess->ctrl_fd);
	priv_sock_init(sess);  //初始化nobody进程和ftp服务进程通信通道

	pid_t pid;
	pid = fork();
	if (pid < 0)
		ERR_EXIT("fork");

	if (pid == 0) {
		// ftp服务进程
		priv_sock_set_child_context(sess); //设置子进程环境
		handle_child(sess);
	} else {
		// nobody进程
		priv_sock_set_parent_context(sess);  //设置父进程环境
		handle_parent(sess);
	}
}

