#include "privparent.h"
#include "privsock.h"
#include "sysutil.h"
#include "tunable.h"

static void privop_pasv_get_data_sock(session_t *sess);  
static void privop_pasv_active(session_t *sess);
static void privop_pasv_listen(session_t *sess);
static void privop_pasv_accept(session_t *sess);

int capset(cap_user_header_t hdrp, const cap_user_data_t datap) //让nobody进程有绑定系统端口的功能
{
	return syscall(__NR_capset, hdrp, datap); //__NR_capset是系统调用号，调用了内核的接口，外部没有实现这个接口
												//平时用的系统调用也是这种方式封装实现的，例如bind()，内部是（syscall(_NR_bind....)
}

void minimize_privilege(void)  //让nobody进程有绑定系统端口的功能
{
	struct passwd *pw = getpwnam("nobody");
	if (pw == NULL)
		return;

	if (setegid(pw->pw_gid) < 0)
		ERR_EXIT("setegid");
	if (seteuid(pw->pw_uid) < 0)
		ERR_EXIT("seteuid");


	struct __user_cap_header_struct cap_header;
	struct __user_cap_data_struct cap_data;

	memset(&cap_header, 0, sizeof(cap_header));
	memset(&cap_data, 0, sizeof(cap_data));

	cap_header.version = _LINUX_CAPABILITY_VERSION_1;
	cap_header.pid = 0;

	__u32 cap_mask = 0; //__u32 无符号32整数
	cap_mask |= (1 << CAP_NET_BIND_SERVICE);  //绑定特权端口权限

	cap_data.effective = cap_data.permitted = cap_mask;
	cap_data.inheritable = 0;  //新的进程不允许集成capabilites

	capset(&cap_header, &cap_data);
}

void handle_parent(session_t *sess)
{
	minimize_privilege();

	char cmd;
	while (1) {
		//read(sess->parent_fd, &cmd, 1);
		cmd = priv_sock_get_cmd(sess->parent_fd);  //nobody进程从ftp进程接收命令
		// 解析内部命令
		// 处理内部命令
		switch (cmd) {
		case PRIV_SOCK_GET_DATA_SOCK:
			privop_pasv_get_data_sock(sess);
			break;
		case PRIV_SOCK_PASV_ACTIVE:
			privop_pasv_active(sess);
			break;
		case PRIV_SOCK_PASV_LISTEN:
			privop_pasv_listen(sess);
			break;
		case PRIV_SOCK_PASV_ACCEPT:
			privop_pasv_accept(sess);
			break;
		
		}
	}
}

static void privop_pasv_get_data_sock(session_t *sess)  //主动模式数据连接
{
	/*
	nobody进程接收PRIV_SOCK_GET_DATA_SOCK命令
进一步接收一个整数，也就是port
接收一个字符串，也就是ip

fd = socket 
bind(20)
connect(ip, port);

OK
send_fd
BAD
*/
	unsigned short port = (unsigned short)priv_sock_get_int(sess->parent_fd);
	char ip[16] = {0};
	priv_sock_recv_buf(sess->parent_fd, ip, sizeof(ip));

	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = inet_addr(ip);

	int fd = tcp_client(20);
	if (fd == -1) {
		priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_BAD);
		return;
	}
	if (connect_timeout(fd, &addr, tunable_connect_timeout) < 0) {
		close(fd);
		priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_BAD);
		return;
	}

	priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_OK);
	priv_sock_send_fd(sess->parent_fd, fd);
	close(fd);
}

static void privop_pasv_active(session_t *sess)  //激活被动模式
{
	int active;
	if (sess->pasv_listen_fd != -1) {
		active = 1;
	} else {
		active = 0;
	}

	priv_sock_send_int(sess->parent_fd, active);
}

static void privop_pasv_listen(session_t *sess)
{
	char ip[16] = {0};
	getlocalip(ip);

	sess->pasv_listen_fd = tcp_server(ip, 0); //监听成功会返回1，说明被动模式建立成功
	struct sockaddr_in addr;
	socklen_t addrlen = sizeof(addr);
	if (getsockname(sess->pasv_listen_fd, (struct sockaddr *)&addr, &addrlen) < 0) { //getsockname获取连接套接字本地地址信息，getpeername()获取对端地址信息
		ERR_EXIT("getsockname");
	}

	unsigned short port = ntohs(addr.sin_port);

	priv_sock_send_int(sess->parent_fd, (int)port);
}

static void privop_pasv_accept(session_t *sess)
{
	int fd = accept_timeout(sess->pasv_listen_fd, NULL, tunable_accept_timeout);
	close(sess->pasv_listen_fd); //数据连接建立完成，关闭监听套接字
	sess->pasv_listen_fd = -1;

	if (fd == -1) {
		priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_BAD);
		return;
	}

	priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_OK);
	priv_sock_send_fd(sess->parent_fd, fd);
	close(fd); //关闭描述符，nobody进程不与客户端通信
}

