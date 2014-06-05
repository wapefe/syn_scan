syn_scan.out:syn_scan.cpp csyn.o cread_conf.o
	g++ -g -o syn_scan.out syn_scan.cpp csyn.o cread_conf.o
csyn.o:csyn.cpp
	g++ -g -c csyn.cpp
cread_conf.o:cread_conf.cpp
	g++ -g -c cread_conf.cpp
clean:
	-rm *.out
	-rm *.o
	-touch *