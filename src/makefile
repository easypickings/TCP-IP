testTCP: testTCPClient.cpp testTCPServer.cpp device.o ip.o arp.o etherframe.o router.o tcp.o socket.o
	g++ -Og -g -o testTCPClient testTCPClient.cpp device.o ip.o arp.o etherframe.o router.o tcp.o socket.o -lpcap -pthread -fsanitize=address
	g++ -Og -g -o testTCPServer testTCPServer.cpp device.o ip.o arp.o etherframe.o router.o tcp.o socket.o -lpcap -pthread -fsanitize=address
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
tcp.o: tcp.cpp
	g++ -c -Og -g -o tcp.o tcp.cpp -lpcap -pthread -fsanitize=address
socket.o: socket.cpp
	g++ -c -Og -g -o socket.o socket.cpp -lpcap -pthread -fsanitize=address

clean:
	rm -rf testTCPClient testTCPServer *.o
