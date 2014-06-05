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

	unsigned int ips;
	inet_pton(AF_INET, plocal_ip, &ips);
	char *pip = (char*)(void*)&ips;
	ip_head_initial.source_address[0] = *pip;
	ip_head_initial.source_address[1] = *(pip + 1);
	ip_head_initial.source_address[2] = *(pip + 2);
	ip_head_initial.source_address[3] = *(pip + 3);

	char *pport = (char*)(void*)&nport;
	tcp_head_initial.source_port[0] = *(pport + 1);
	tcp_head_initial.source_port[1] = *pport;
}
void csyn::make_ip()
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
	/*
	ip_head_initial.source_address[0] = 192;
	ip_head_initial.source_address[1] = 168;
	ip_head_initial.source_address[2] = 1;
	ip_head_initial.source_address[3] = 103;
	ip_head_initial.dest_address[0] = 192;
	ip_head_initial.dest_address[1] = 168;
	ip_head_initial.dest_address[2] = 1;
	ip_head_initial.dest_address[3] = 100;
	*/
}
void csyn::ip_check_sum()
{
	unsigned int chksum = 0;
	unsigned short tmp;
	char *ptmp = (char*)(void*)&tmp;
	char *pshort = (char*)(void*)&ip_head_initial;
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
	memcpy(&ip_head_initial.check_sum[0], ptmp + 1, 1);
	memcpy(&ip_head_initial.check_sum[1], ptmp, 1);
}
void csyn::make_tcp()
{
	/*
	tcp_head_initial.source_port[0] = 0x2f;
	tcp_head_initial.source_port[1] = 0x9b;
	tcp_head_initial.dest_port[0] = 0x00;
	tcp_head_initial.dest_port[1] = 136;
	*/
	tcp_head_initial.seq_num[0] = 0xca;
	tcp_head_initial.seq_num[1] = 0xb3;
	tcp_head_initial.seq_num[2] = 0x68;
	tcp_head_initial.seq_num[3] = 0x7a;
	tcp_head_initial.ack_num[0] = 0x0;
	tcp_head_initial.ack_num[1] = 0x0;
	tcp_head_initial.ack_num[2] = 0x0;
	tcp_head_initial.ack_num[3] = 0x0;//because ack is not set, ack should be 0
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
void csyn::tcp_check_sum()
{
	unsigned int chksum = 0;
	unsigned short tmp;
	char *ptmp = (char*)(void*)&tmp;
	char *pshort = (char*)(void*)&tcp_head_initial;
	for (int i = 0; i < 10; ++i)
	{
		memcpy(ptmp + 1, pshort + i* 2, 1);
		memcpy(ptmp, pshort + i * 2 + 1, 1);

		chksum += tmp;
	}

	pshort = ip_head_initial.source_address;
	memcpy(ptmp + 1, pshort, 1);
	memcpy(ptmp, pshort+ 1, 1);
	chksum += tmp;
	memcpy(ptmp + 1, pshort + 2, 1);
	memcpy(ptmp, pshort + 3, 1);
	chksum += tmp;
	pshort = ip_head_initial.dest_address;
	memcpy(ptmp + 1, pshort, 1);
	memcpy(ptmp, pshort+ 1, 1);
	chksum += tmp;
	memcpy(ptmp + 1, pshort + 2, 1);
	memcpy(ptmp, pshort + 3, 1);
	chksum += tmp;

	pshort = ip_head_initial.len;
	memcpy(ptmp + 1, pshort, 1);
	memcpy(ptmp, pshort + 1, 1);
	chksum += (tmp - 20);

	chksum += 0x06;


	unsigned int ui1 = (chksum>>16);
	unsigned int ui2 = (chksum&0xffff);
	chksum = ui1 + ui2;
	chksum = (~chksum)&0xffff;

	ptmp = (char*)(void*)&chksum;
	memcpy(&tcp_head_initial.check_sum[0], ptmp + 1, 1);
	memcpy(&tcp_head_initial.check_sum[1], ptmp, 1);
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
	//memcpy(send_buf, &ip_head_initial, sizeof(ip_head_initial));
	//memcpy(send_buf + sizeof(ip_head_initial), &tcp_head_initial, sizeof(tcp_head_initial));
	memcpy(send_buf, &tcp_head_initial, sizeof(tcp_head_initial));
	int nLens = sizeof(tcp_head_initial);

	struct sockaddr_in dest_addr;
	memset((void*)&dest_addr, 0, sizeof(dest_addr));
	dest_addr.sin_family = AF_INET;
	dest_addr.sin_port = htons(syn_host_port);
	/*
	cout<<"sendto ip:"<<syn_host_ip<<endl;
	cout<<"sendto port:"<<syn_host_port<<endl;
	*/
	inet_aton(syn_host_ip, &dest_addr.sin_addr);
	
	sendto(nsock, send_buf, nLens, 0,(struct sockaddr*)&dest_addr, sizeof(dest_addr));
	
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

	unsigned int ips;
	inet_pton(AF_INET, pdest_ip, &ips);
	char *pip = (char*)(void*)&ips;
	ip_head_initial.dest_address[0] = *pip;
	ip_head_initial.dest_address[1] = *(pip + 1);
	ip_head_initial.dest_address[2] = *(pip + 2);
	ip_head_initial.dest_address[3] = *(pip + 3);

	char *pport = (char*)(void*)&nport;
	tcp_head_initial.dest_port[0] = *(pport + 1);
	tcp_head_initial.dest_port[1] = *pport;
}

void csyn::syn_close()
{
	tcp_head_initial.flags = 0x04;
	tcp_head_initial.check_sum[0] = 0;
	tcp_head_initial.check_sum[1] = 0;
	tcp_check_sum();
	
	sendtosyn();
}