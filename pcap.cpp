#include <pcap.h>
#include <iostream>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)



using namespace std;


struct ethheader {
	unsigned char destHost[ETHER_ADDR_LEN];
	unsigned char srcHost[ETHER_ADDR_LEN];
	unsigned short etherType;
};

struct ipheader {
 	unsigned char iph_ihl:4;
 	unsigned char iph_ver:4;	
 	unsigned char iph_tos;		
	unsigned short int iph_len;	
	unsigned short int iph_ident;		
	unsigned short int iph_flag:3;
        unsigned short int iph_offset:13;	
	unsigned char iph_ttl;	
	unsigned char iph_protocol;	
	unsigned short int iph_chksum;	
  	struct  in_addr    iph_sourceip;
  	struct  in_addr    iph_destip;
};

struct tcpheader {
	unsigned short tcp_sport;           
    	unsigned short tcp_dport;
    	unsigned int tcp_seq;
    	unsigned int tcp_ack;
    	unsigned char tcp_offx2;
    	unsigned char tcp_flags;
    	unsigned short tcp_win;
    	unsigned short tcp_sum;
    	unsigned short tcp_urp;
};


class packetCapture {
	const char* device;
	char error_buf[PCAP_ERRBUF_SIZE];
	pcap_t* handle;
		
public:
	packetCapture(const char* d) : device(d){
		handle = pcap_open_live(device, 100, 1, 1000, error_buf);
		
		if (handle == nullptr) { cout << "[ERROR]" << error_buf << endl; }
		else {
			cout << "Start to packetCapture" << endl; 
		}
	}
	
	~packetCapture(){
		if (handle != nullptr) { 
			pcap_close(handle); 
			cout << "Stop to packetCapture" << endl;
			printf("\n\n\n\n");
		}
	}
	
	void startCapture(){
		pcap_loop(handle, 10, packetHandler, nullptr);
	}
	
private:
	static void printMACaddress(const unsigned char* mac){
		printf("%02x:%02x:%02x:%02x:%02x:%02x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	}
	
	static void packetHandler(unsigned char* user, const struct pcap_pkthdr* header, const unsigned char* packet){
		struct ethheader* eth = (struct ethheader*)packet;
		struct ipheader* ip = (struct ipheader*)(packet + sizeof(struct ethheader));
		struct tcpheader* tcp = (struct tcpheader*)(packet + sizeof(struct ethheader) + ip->iph_ihl * 4);
		const unsigned char* payloadHex = packet + sizeof(struct ethheader) + (ip->iph_ihl * 4) + 20;
		const unsigned char* payloadStr = packet + sizeof(struct ethheader) + (ip->iph_ihl * 4) + 20;
		int payloadLen = ntohs(ip->iph_len) - (ip->iph_ihl * 4) - 20;
		int len = 0;
		
		if (ntohs(eth->etherType) != 0x800) { return; }
		if (ip->iph_protocol != IPPROTO_TCP) { return; }
		if (ntohs(tcp->tcp_sport) == 443 || ntohs(tcp->tcp_dport) == 443) { return; }
		if (payloadLen == 0) { return; }
			
		cout << "======================== Packet information ========================" << endl;
			
		cout << "MAC Address" << endl;
		cout << "	From: ";
		printMACaddress(eth->srcHost);
		cout << "	To:   ";
		printMACaddress(eth->destHost);
			
		cout << "IP Address" << endl;
		cout << "	From: " << inet_ntoa(ip->iph_sourceip) << endl;
		cout << "	To:   " << inet_ntoa(ip->iph_destip) << endl;
		cout << "	Protocol: TCP" << endl;
		
		cout << "TCP Port" << endl;
		cout << "	From: " << ntohs(tcp->tcp_sport) << endl;
		cout << "	To :  " << ntohs(tcp->tcp_dport) << endl;
		
		cout << "Payload" << endl;
		while (len < payloadLen) {
			for (int j = 0; j < 16; j++) {
				printf("%02X ", *(payloadHex++));
			}
			printf("	|");
			for (int j = 0; j < 16; j++) {
				if (*payloadStr == 0x0A || *payloadStr == 0x0D) {
					printf(".");
				}
				else {
					printf("%c", *payloadStr);
				}
				payloadStr++;
				len++;
			}
			printf("\n");
		}
		printf("\n\n");
	}
};


int main(){
	cout << "To stop, please press Ctrl+C" << endl;

	while (1) {
		packetCapture packet("ens33");
		packet.startCapture();
	}
	return 0;	
}