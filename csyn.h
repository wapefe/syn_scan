
#include <iostream>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <errno.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <netinet/ip.h>
#include <linux/if_ether.h>
#include <unistd.h>
//#include <linux/in.h>

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
	void make_ip();
	void ip_check_sum();

	void make_tcp();
	void tcp_check_sum();

	void sendtosyn();
	void recvsyn();
	bool judge_open();
	void syn_close();

private:
	typedef struct ip_head 
	{
		char ver_and_head_len;
		char serv_type;
		char len[2];
		char identifier[2];
		char flags_offset[2];
		char ttl;
		char protocal;
		char check_sum[2];
		char source_address[4];
		char dest_address[4];

	}ip_head;

	typedef struct tcp_head 
	{
		char source_port[2];
		char dest_port[2];
		char seq_num[4];
		char ack_num[4];
		char head_len_and_lefts;
		char flags;
		char wind[2];
		char check_sum[2];
		char urg_ptr[2];
		//char pdata[4];

	}tcp_head;

private:
	int nsock;
	ip_head ip_head_initial;
	tcp_head tcp_head_initial;

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