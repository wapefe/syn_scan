
#include <iostream>
#include <cstdlib>
#include "csyn.h"
using namespace std;

int main(int argc, char** argv)
{
	unsigned short nport;
	if (argc == 3)
	{
		nport = atoi(*(argv + 2));
	}
	else
	{
		cout<<"no parameter, ./syn_scan.out 192.168.1.100 135"<<endl;
	}
	csyn *syn_scan = new csyn("192.168.1.103", 9891);
	//syn_scan->syn_host("192.168.1.100", 135);
	syn_scan->syn_host(*(argv + 1), nport);
	syn_scan->make_sock();
	syn_scan->make_ip();
	syn_scan->ip_check_sum();
	syn_scan->make_tcp();
	syn_scan->tcp_check_sum();
	syn_scan->sendtosyn();
	syn_scan->recvsyn();
	bool bl = syn_scan->judge_open();

	if (bl)
	{
		cout<<"open"<<endl;
	}
	else
	{
		cout<<"no open"<<endl;
	}
	return 0;
}

