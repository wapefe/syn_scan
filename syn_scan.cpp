
#include <iostream>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <errno.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <netinet/ip.h>

using namespace std;


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
void make_ip(ip_head &head);
void ip_check_sum(ip_head &head);

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
void make_tcp(tcp_head &thead);
void tcp_check_sum(tcp_head &thead, ip_head &ihead);

int main(int argc, char** argv)
{
	
	int nsock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (nsock < 0)
	{
		perror("sock");
		exit(1);
	}
	/*
	struct sockaddr_in bind_sock;
	memset((void*)&bind_sock, 0, sizeof(bind_sock));
	bind_sock.sin_family = AF_INET;
	inet_aton("192.168.1.103", &bind_sock.sin_addr);
	bind_sock.sin_port = htons(8091);
	bind(nsock, (sockaddr*)&bind_sock,sizeof(bind_sock));
	*/
	bool bopt = true;
	int nret = setsockopt(nsock, IPPROTO_IP, IP_HDRINCL, (void*)&bopt, sizeof(bopt));
	
	ip_head ip_head_initial;
	make_ip(ip_head_initial);
	ip_check_sum(ip_head_initial);

	tcp_head tcp_head_initial;
	make_tcp(tcp_head_initial);
	tcp_check_sum(tcp_head_initial, ip_head_initial);

	char send_buf[256] = {0};
	char rcv_buf[256] = {0};

	memcpy(send_buf, &ip_head_initial, sizeof(ip_head_initial));
	memcpy(send_buf + sizeof(ip_head_initial), &tcp_head_initial, sizeof(tcp_head_initial));
	int nLens = sizeof(ip_head_initial) + sizeof(tcp_head_initial);
	
	struct sockaddr_in dest_addr;
	memset((void*)&dest_addr, 0, sizeof(dest_addr));
	dest_addr.sin_family = AF_INET;
	dest_addr.sin_port = htons(135);
	char *pDest = "192.168.1.100";
	inet_aton(pDest, &dest_addr.sin_addr);
	sendto(nsock, send_buf, nLens, 0,(struct sockaddr*)&dest_addr, sizeof(dest_addr));

	struct sockaddr_in recv_addr;
	nLens = sizeof(recv_addr);
	recvfrom(nsock, rcv_buf, 256, 0,(struct sockaddr*)&recv_addr, (socklen_t*)&nLens);
	cout<<"rcv ip:"<<inet_ntoa(recv_addr.sin_addr)<<endl;
	cout<<"rcv port:"<<ntohs(recv_addr.sin_port)<<endl;
	cout<<rcv_buf<<endl;
	return 0;
}
void make_ip(ip_head &ip_head_initial)
{
	ip_head_initial.ver_and_head_len = 0x45;
	ip_head_initial.serv_type = 0x00;
	ip_head_initial.len[0] = 0x00;
	ip_head_initial.len[1] = 40;
	ip_head_initial.identifier[0] = 0x0e;
	ip_head_initial.identifier[1] = 0x21;
	ip_head_initial.flags_offset[0] = 0x40;
	ip_head_initial.flags_offset[1] = 0x00;
	ip_head_initial.ttl = 0x40;
	ip_head_initial.protocal = 0x06;
	ip_head_initial.check_sum[0] = 0x00;
	ip_head_initial.check_sum[1] = 0x00;
	ip_head_initial.source_address[0] = 192;
	ip_head_initial.source_address[1] = 168;
	ip_head_initial.source_address[2] = 1;
	ip_head_initial.source_address[3] = 103;
	ip_head_initial.dest_address[0] = 192;
	ip_head_initial.dest_address[1] = 168;
	ip_head_initial.dest_address[2] = 1;
	ip_head_initial.dest_address[3] = 100;
}
void ip_check_sum(ip_head &head)
{
	unsigned int chksum = 0;
	unsigned short tmp;
	char *ptmp = (char*)(void*)&tmp;
	char *pshort = (char*)(void*)&head;
	for (int i = 0; i < 10; ++i)
	{
		memcpy(ptmp + 1, pshort + i* 2, 1);
		memcpy(ptmp, pshort + i * 2 + 1, 1);

		chksum += tmp;
	}
	unsigned int ui1 = (chksum>>16);
	unsigned int ui2 = (chksum&0xffff);
	chksum = ui1 + ui2;
	chksum = (~chksum)&0xffff;

	ptmp = (char*)(void*)&chksum;
	memcpy(&head.check_sum[0], ptmp + 1, 1);
	memcpy(&head.check_sum[1], ptmp, 1);
}
void make_tcp(tcp_head &tcp_head_initial)
{
	tcp_head_initial.source_port[0] = 0x2f;
	tcp_head_initial.source_port[1] = 0x9b;
	tcp_head_initial.dest_port[0] = 0x00;
	tcp_head_initial.dest_port[1] = 135;
	tcp_head_initial.seq_num[0] = 0xca;
	tcp_head_initial.seq_num[1] = 0xb3;
	tcp_head_initial.seq_num[2] = 0x68;
	tcp_head_initial.seq_num[3] = 0x7a;
	tcp_head_initial.ack_num[0] = 0xb7;
	tcp_head_initial.ack_num[1] = 0xed;
	tcp_head_initial.ack_num[2] = 0xcb;
	tcp_head_initial.ack_num[3] = 0x85;
	tcp_head_initial.head_len_and_lefts = 0x50;
	tcp_head_initial.flags = 0x02;
	tcp_head_initial.wind[0] = 0xfe;
	tcp_head_initial.wind[1] = 0xf3;
	tcp_head_initial.check_sum[0] = 0x00;
	tcp_head_initial.check_sum[1] = 0x00;
	tcp_head_initial.urg_ptr[0] = 0x00;
	tcp_head_initial.urg_ptr[1] = 0x00;
	/*
	tcp_head_initial.pdata[0] = 0x61;
	tcp_head_initial.pdata[1] = 0x62;
	tcp_head_initial.pdata[2] = 0x63;
	tcp_head_initial.pdata[3] = 0x64;
	*/
}
void tcp_check_sum(tcp_head &thead, ip_head &ihead)
{
	unsigned int chksum = 0;
	unsigned short tmp;
	char *ptmp = (char*)(void*)&tmp;
	char *pshort = (char*)(void*)&thead;
	for (int i = 0; i < 10; ++i)
	{
		memcpy(ptmp + 1, pshort + i* 2, 1);
		memcpy(ptmp, pshort + i * 2 + 1, 1);

		chksum += tmp;
	}

	pshort = ihead.source_address;
	memcpy(ptmp + 1, pshort, 1);
	memcpy(ptmp, pshort+ 1, 1);
	chksum += tmp;
	memcpy(ptmp + 1, pshort + 2, 1);
	memcpy(ptmp, pshort + 3, 1);
	chksum += tmp;
	pshort = ihead.dest_address;
	memcpy(ptmp + 1, pshort, 1);
	memcpy(ptmp, pshort+ 1, 1);
	chksum += tmp;
	memcpy(ptmp + 1, pshort + 2, 1);
	memcpy(ptmp, pshort + 3, 1);
	chksum += tmp;

	pshort = ihead.len;
	memcpy(ptmp + 1, pshort, 1);
	memcpy(ptmp, pshort + 1, 1);
	chksum += (tmp - 20);

	chksum += 0x06;


	unsigned int ui1 = (chksum>>16);
	unsigned int ui2 = (chksum&0xffff);
	chksum = ui1 + ui2;
	chksum = (~chksum)&0xffff;

	ptmp = (char*)(void*)&chksum;
	memcpy(&thead.check_sum[0], ptmp + 1, 1);
	memcpy(&thead.check_sum[1], ptmp, 1);
}
