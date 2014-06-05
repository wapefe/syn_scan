
#include <iostream>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <errno.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>


#include <netinet/tcp.h>

using namespace std;

#ifndef _CSYN_H_
#define _CSYN_H_


class csyn
{
public:
	csyn(void);
	~csyn(void);
	csyn(const char *plocal_ip, unsigned short nport);
	void make_sock();
	void syn_host(const char *pdest_ip, int nport);

	void make_tcp();
	void tcp_check_sum();

	void sendtosyn();
	void recvsyn();
	bool judge_open();
	void syn_close();

private:
	struct tcphdr tcp_head_initial;

private:
	int nsock;

	char send_buf[256];
	char rcv_buf[256];
	int recv_num;

private:
	unsigned short syn_host_port;
	char syn_host_ip[16];
	unsigned short syn_local_port;
	char syn_local_ip[16];
};

#endif