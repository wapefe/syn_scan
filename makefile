syn_scan.out:syn_scan.cpp csyn.o
	g++ -g -o syn_scan.out syn_scan.cpp csyn.o
csyn.o:csyn.cpp
	g++ -g -c csyn.cpp
clean:
	-rm *.out
	-rm *.o
	-touch *