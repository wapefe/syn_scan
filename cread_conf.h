
#include <iostream>
#include <map>
#include <fstream>
#include <string>
#include <cstdlib>
using namespace std;

#ifndef _READ_CONF_H_
#define _READ_CONF_H_

class cread_conf
{
public:
	cread_conf(void);
	~cread_conf(void);
	void file_open(char *file_name);
	void get_conf();
	void file_close();
	string get_local_ip();
	int get_local_port();
	string get_scan_ip();
	string get_scan_port();

	void count_port(string const &scan_port, int &nstart, int &nend);
private:
	fstream file_read;
	typedef map<string, string> mss;
	mss map_store;
	typedef pair<string, string> pair_map;
	mss::iterator it;
};

#endif



