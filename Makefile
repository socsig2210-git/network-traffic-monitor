all: pcap_ex hello

pcap_ex: pcap_ex.c
	gcc -o pcap_ex pcap_ex.c -lpcap

hello: hello.c
	gcc -o hello hello.c -lpcap

clean:
	rm -rf pcap_ex