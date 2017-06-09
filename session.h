#ifndef _SESSION_H_
#define _SESSION_H_

#include "common.h"

typedef struct session
{
	// 控制连接
	uid_t uid;
	int ctrl_fd;
	char cmdline[MAX_COMMAND_LINE];
	char cmd[MAX_COMMAND];
	char arg[MAX_ARG];

	// 数据连接
	struct sockaddr_in *port_addr;
	int pasv_listen_fd;  //被动模式监听套接字，用于判断被动模式是否处于激活状态，被动模式下accept（listen_fd)
	int data_fd;
	int data_process;

	// 限速
	unsigned int bw_upload_rate_max; //上传最大速率
	unsigned int bw_download_rate_max; //下载最大速率
	long bw_transfer_start_sec;  //开始传输时间
	long bw_transfer_start_usec;


	// 父子进程通道
	int parent_fd;
	int child_fd;

	// FTP协议状态
	int is_ascii;
	long long restart_pos;  //记录断点续传的位置
	char *rnfr_name;  //将要被重命名的文件名
	int abor_received;

	// 连接数限制
	unsigned int num_clients;  //总连接数
	unsigned int num_this_ip;  //当前ip连接数
} session_t;

void begin_session(session_t *sess);

#endif /* _SESSION_H_ */

