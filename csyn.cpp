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

	//超时
	struct timeval timeouts = {1, 0};
	setsockopt(nsock, SOL_SOCKET, SO_RCVTIMEO, &timeouts, sizeof(timeouts));
	
}
void csyn::close_sock()
{
	close(nsock);
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

bool csyn::recv_and_judge()
{
	bool bflag = false;
	bool bcapture_return = false;
	while (true)
	{
		recv_num = read(nsock, rcv_buf, 256);
		if (recv_num <= 0)
		{
			break;
		}
		if (check_tcp(rcv_buf, recv_num, bcapture_return))
		{
			bflag = true;
		}
		
	}
	return bflag;
}
bool csyn::check_tcp(char cbuf[], int nlen, bool &bcapture_return)
{
	
	//检测ack num是否为seq num + 1
	
	unsigned int *ptmp = (unsigned int *)cbuf + (cbuf[0] & 0x0f) + 2;
	if (ntohl(*ptmp) == nsep_num + syn_host_port +1)
	{
		bcapture_return = true;
		unsigned short ustmp = (*(ptmp + 1) & 0xffff) >> 8;
		if ((ustmp ^ 0x012) == 0)
		{
			return true;
		}
		if ((ustmp ^ 0x014) == 0)
		{
			return false;
		}
		
	}
	else
	{
		return false;
	}
	
}
void csyn::host_ip(const char *pdest_ip)
{
	strcpy(syn_host_ip, pdest_ip);
	srand(time(NULL));
	nsep_num = rand();
}
void csyn::host_port(unsigned short nport)
{
	syn_host_port = nport;
}

void csyn::host_close()
{
	tcp_head_initial.fin = 1;
	tcp_check_sum();
	
	sendtosyn();
}

void csyn::make_tcp()
{
	memset(&tcp_head_initial, 0, sizeof(tcp_head_initial));
	
	tcp_head_initial.source = htons(syn_local_port);
	tcp_head_initial.dest = htons(syn_host_port);
	
	tcp_head_initial.seq = htonl(nsep_num + syn_host_port);
	
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
	unsigned short n1, n2;
	ip_token(syn_local_ip, n1, n2);
	ncheck_sum += n1;
	ncheck_sum += n2;
	ip_token(syn_host_ip, n1, n2);
	ncheck_sum += n1;
	ncheck_sum += n2;
	//tcp包的长度为20，协议为6
	ncheck_sum += (20 + 6);

	n1 = (ncheck_sum >> 16);
	n2 = (ncheck_sum & 0xffff);
	ncheck_sum = n1 + n2;
	short sum = (~ncheck_sum) & 0xffff;

	tcp_head_initial.check = htons(sum);
}

void csyn::ip_token(char ips[], unsigned short &n1, unsigned short &n2)
{
	 unsigned int ntmp;
	 inet_pton(AF_INET, ips, &ntmp);
	 n1 = htons( ntmp >> 16);
	 n2 = htons(ntmp & 0xffff);
}