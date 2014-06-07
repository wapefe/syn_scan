
#include <iostream>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <errno.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <cmath>
#include <ctime>
#include <unistd.h>
#include <fcntl.h>

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
	void close_sock();
	void host_ip(const char *pdest_ip);
	void host_port(unsigned short nport);

	void make_tcp();
	void tcp_check_sum();

	void sendtosyn();
	bool recv_and_judge();
	void host_close();

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

	unsigned int nsep_num;
	void ip_token(char ips[], unsigned short &n1, unsigned short &n2);
	bool check_tcp(char cbuf[], int nlen, bool &bcapture_return);
};

#endif