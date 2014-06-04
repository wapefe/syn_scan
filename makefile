syn_scan.out:syn_scan.cpp
	g++ -g -o syn_scan.out syn_scan.cpp
clean:
	-rm *.out
	-touch *