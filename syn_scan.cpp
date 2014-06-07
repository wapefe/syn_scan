
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
	
	fstream file_write;
	file_write.open("syn_scan.txt", ios::out);

	syn_scan->host_ip(scan_ip.c_str());
	for (int nport = nstart; nport <= nend; ++nport)
	{
	
		syn_scan->host_port(nport);
		
		syn_scan->make_tcp();
		syn_scan->tcp_check_sum();
		syn_scan->sendtosyn();
		
		bool bl = syn_scan->recv_and_judge();

		if (bl)
		{
			cout<<nport<<" open"<<endl;
			syn_scan->host_close();
			file_write<<"ip:"<<scan_ip<<","<<"port:"<<nport<<";"<<endl;
		}
		else
		{
			cout<<nport<<" no open"<<endl;
		}

	}
	file_write.close();
	syn_scan->close_sock();
	delete syn_scan;
	return 0;
}

