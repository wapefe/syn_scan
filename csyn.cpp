#include "csyn.h"


csyn::csyn(void)
{
}

csyn::~csyn(void)
{
}
csyn::csyn(const char *plocal_ip, unsigned short nport)
{
	syn_local_port = nport;
	strcpy(syn_local_ip, plocal_ip);
	
}

bool csyn::judge_open()
{
	if (recv_num <= 0)
	{
		return false;
	}
	char c = (*rcv_buf)&(0x0f);
	char *ptcp_head = rcv_buf + c * 4 + 3 * 4 + 1;

	if ((*ptcp_head ^ 0x12) == 0)
	{
		return true;
	}
	return false;
}

void csyn::make_sock()
{
	nsock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (nsock < 0)
	{
		perror("sock");
		exit(1);
	}
	
	struct sockaddr_in bind_sock;
	memset((void*)&bind_sock, 0, sizeof(bind_sock));
	bind_sock.sin_family = AF_INET;
	inet_aton(syn_local_ip, &bind_sock.sin_addr);
	bind_sock.sin_port = htons(syn_local_port);
	bind(nsock, (sockaddr*)&bind_sock,sizeof(bind_sock));
	
	/*
	bool bopt = true;
	int nret = setsockopt(nsock, IPPROTO_IP, IP_HDRINCL, (void*)&bopt, sizeof(bopt));
	*/

	struct timeval tv_out;
	tv_out.tv_sec = 3;
	tv_out.tv_usec = 0;
	setsockopt(nsock,SOL_SOCKET,SO_RCVTIMEO, (char*)&tv_out, sizeof(tv_out));
}

void csyn::sendtosyn()
{
	struct sockaddr_in dest_addr;
	memset((void*)&dest_addr, 0, sizeof(dest_addr));
	dest_addr.sin_family = AF_INET;
	dest_addr.sin_port = htons(syn_host_port);
	/*
	cout<<"sendto ip:"<<syn_host_ip<<endl;
	cout<<"sendto port:"<<syn_host_port<<endl;
	*/
	inet_aton(syn_host_ip, &dest_addr.sin_addr);
	memcpy(send_buf, &tcp_head_initial, sizeof(tcp_head_initial));
	sendto(nsock,send_buf, sizeof(tcp_head_initial), 0,(struct sockaddr*)&dest_addr, sizeof(dest_addr));
	
}

void csyn::recvsyn()
{
	struct sockaddr_in recv_addr;
	int nLens = sizeof(recv_addr);
	
	recv_num = read(nsock, rcv_buf, 256);
}

void csyn::syn_host(const char *pdest_ip, int nport)
{
	syn_host_port = nport;
	strcpy(syn_host_ip, pdest_ip);

}

void csyn::syn_close()
{
	
	tcp_check_sum();
	
	sendtosyn();
}

void csyn::make_tcp()
{
	memset(&tcp_head_initial, 0, sizeof(tcp_head_initial));
	
	tcp_head_initial.source = htons(syn_local_port);
	tcp_head_initial.dest = htons(syn_host_port);
	tcp_head_initial.seq = htonl(12345);
	
	tcp_head_initial.doff = 5;
	tcp_head_initial.window = htons(65535);
	
	tcp_head_initial.syn = 1;
	/*
	tcp_head_initial.source = htons(4667);
	tcp_head_initial.dest = htons(22);
	tcp_head_initial.seq = htonl(0x4b9f4b1e);
	tcp_head_initial.ack_seq = htonl(0x800cfeb1);
	tcp_head_initial.doff = 5;
	tcp_head_initial.ack = 1;
	tcp_head_initial.window = htons(16144);
*/
	
}

void csyn::tcp_check_sum()
{
	unsigned int ncheck_sum = 0;
	char *ptmp = (char *)(void*)&tcp_head_initial;
	unsigned short ustmp;
	char *pus = (char *)(void*)&ustmp;
	for (int i = 0; i < 10; ++i)
	{
		*(pus + 1) = *ptmp;
		*pus = *(ptmp + 1);
		ptmp += 2;
		ncheck_sum += ustmp;
	}
	ncheck_sum += 0xc0A8;
	ncheck_sum += 0x0164;
	ncheck_sum += 0xc0A8;
	ncheck_sum += 0x0167;
	ncheck_sum += (20 + 6);

	int n1 = (ncheck_sum >> 16);
	int n2 = (ncheck_sum & 0xffff);
	ncheck_sum = n1 + n2;
	short sum = (~ncheck_sum) & 0xffff;

	tcp_head_initial.check = htons(sum);
}

