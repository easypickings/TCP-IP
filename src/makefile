test: test.cpp device.o ip.o arp.o etherframe.o router.o
	g++ -Og -g -o test test.cpp device.o ip.o arp.o etherframe.o router.o -lpcap -pthread -fsanitize=address
device.o: device.cpp
	g++ -c -Og -g -o device.o device.cpp -lpcap -pthread -fsanitize=address
ip.o: ip.cpp
	g++ -c -Og -g -o ip.o ip.cpp -lpcap -pthread -fsanitize=address
arp.o: arp.cpp
	g++ -c -Og -g -o arp.o arp.cpp -lpcap -pthread -fsanitize=address
etherframe.o: etherframe.cpp
	g++ -c -Og -g -o etherframe.o etherframe.cpp -lpcap -pthread -fsanitize=address
router.o: router.cpp
	g++ -c -Og -g -o router.o router.cpp -lpcap -pthread -fsanitize=address
clean:
	rm -rf test *.o
