
#include "cread_conf.h"

cread_conf::cread_conf(void)
{
}


cread_conf::~cread_conf(void)
{
}

void cread_conf::file_open(char *file_name)
{
	file_read.open(file_name, ios::in);
}
void cread_conf::get_conf()
{
	char cbuf[256];
	int nPos;
	int nLen;
	while (file_read.getline(cbuf, 256))
	{
		cout<<cbuf<<endl;
		if (cbuf[0] != '#' && cbuf[0] != '\r' && cbuf[0] != '\0')
		{
			nPos = 0;
			while (cbuf[nPos] != ' ' && cbuf[nPos] != '=')
			{
				nPos++;
			}
			string s1(cbuf, cbuf + nPos);

			nPos++;
			while (cbuf[nPos] == ' ' || cbuf[nPos] == '=')
			{
				nPos++;
			}
			nLen = nPos;
			nPos++;
			while (cbuf[nPos] != '\r' && cbuf[nPos] != '\0')
			{
				nPos++;
			}
			string s2(cbuf+ nLen, cbuf + nPos);
			map_store.insert(pair_map(s1, s2));
		}
	}
}
void cread_conf::file_close()
{
	file_read.close();
}

string cread_conf::get_local_ip()
{
	it = map_store.find("local_ip");
	return it->second;
}
int cread_conf::get_local_port()
{
	it = map_store.find("local_port");
	return atoi(it->second.c_str());
}

string cread_conf::get_scan_ip()
{
	it = map_store.find("scan_ip");
	return it->second;
}
string cread_conf::get_scan_port()
{
	it = map_store.find("scan_port");
	return it->second;
}

void cread_conf::count_port(string const &scan_port, int &nstart, int &nend)
{
	char cbuf[33];
	int nPos = 0;
	while (scan_port[nPos] != '\0' && scan_port[nPos] != '-')
	{
		cbuf[nPos] = scan_port[nPos];
		nPos++;
	}
	cbuf[nPos] = '\0';
	nstart = atoi(cbuf);

	int n = 0;
	nPos++;
	while (scan_port[nPos] != '\0')
	{
		cbuf[n] = scan_port[nPos];
		n++;
		nPos++;
	}
	cbuf[n] = '\0';
	nend = atoi(cbuf);
}

