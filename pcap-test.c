#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <libnet/libnet-headers.h>

void print_mac(uint8_t *mac_addr);
void print_IP(uint32_t IP_addr);
void print_payload(const u_char* payload, int len);
void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}
void print_mac(uint8_t *mac_addr){
	for(int i=0;i<6;i++){
		printf("%02x",mac_addr[i]);
		if(i!=5){
			printf(":");
		}
	}
	printf("\n");
}
void print_IP(uint32_t IP_addr){
	for(int i=0;i<4;i++){
		printf("%d",(IP_addr>>i*8)&0xFF);
		if(i!=3){
			printf(".");
		}
	}
	printf("\n");
}

void print_payload(const u_char* payload, int len) {
	int max_len=0;
	if(len>=20){
		max_len=20;
	}
	else{
		max_len=len;
	}
    for (int i = 0; i < max_len; ++i) {
        printf("%02x ", payload[i]);
    }
    printf("\n");
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res,
					pcap_geterr(pcap));
			break;
		}
		struct libnet_ethernet_hdr* e_header = (struct libnet_ethernet_hdr*)packet;
		printf("Src mac:");
		print_mac(e_header->ether_shost);
		printf("Dst mac:");
		print_mac(e_header->ether_dhost);

		int front_len = sizeof(struct libnet_ethernet_hdr);
		struct libnet_ipv4_hdr* ip_header = (struct libnet_ipv4_hdr*)(packet + front_len);
		printf("Src IP:");
		print_IP(ip_header->ip_src.s_addr);
		printf("Dst IP: ");
		print_IP(ip_header->ip_dst.s_addr);
		
		front_len += sizeof(struct libnet_ipv4_hdr);
		struct libnet_tcp_hdr* tcp_header = (struct libnet_tcp_hdr*)(packet +front_len);
		printf("Src Port: %d\n", ntohs(tcp_header->th_sport));
		printf("Dst Port: %d\n", ntohs(tcp_header->th_dport));
		
		
		front_len += sizeof(struct libnet_tcp_hdr);
		if (header->caplen-front_len > 0) {
          		 const u_char* payload = packet + front_len;
           		 printf("Payload : ");
           		 print_payload(payload, header->caplen-front_len);
       		} 
		
		printf("%u bytes captured\n", header->caplen);
	}

	pcap_close(pcap);
}
