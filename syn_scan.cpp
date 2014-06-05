
#include <iostream>
#include <cstdlib>
#include "csyn.h"
#include "cread_conf.h"
#include <fstream>
#include <string>
using namespace std;

int main(int argc, char** argv)
{
	cread_conf *rconf = new cread_conf;
	rconf->file_open("syn_scan.conf");
	rconf->get_conf();
	string local_ip = rconf->get_local_ip();
	int local_port = rconf->get_local_port();
	string scan_ip = rconf->get_scan_ip();
	string scan_port = rconf->get_scan_port();
	rconf->file_close();
	
	int nstart = 0;
	int nend = 0;
	rconf->count_port(scan_port, nstart, nend);
	delete rconf;

	csyn *syn_scan = new csyn(local_ip.c_str(), local_port);
	syn_scan->make_sock();
	/*
	fstream file_write;
	file_write.open("syn_scan.txt", ios::out);
	for (int nport = nstart; nport <= nend; ++nport)
	{
	*/
		syn_scan->syn_host(scan_ip.c_str(), 135);
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
			syn_scan->syn_close();
			//file_write<<"ip:"<<scan_ip<<","<<"port:"<<nport<<";"<<endl;
		}
		else
		{
			cout<<"no open"<<endl;
		}
/*
	}
	file_write.close();
	*/
	delete syn_scan;
	return 0;
}

