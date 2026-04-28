#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct iphdr *ip = (struct iphdr *)(packet + 14);
    struct tcphdr *tcp = (struct tcphdr *)(packet + 14 + ip->ihl * 4);

    int ip_header_len = ip->ihl * 4;
    int tcp_header_len = tcp->doff * 4;
    int total_header = 14 + ip_header_len + tcp_header_len;
    int data_len = header->caplen - total_header;

    if (data_len > 0) {
        const u_char *data = packet + total_header;
        printf("Data: ");
        for (int i = 0; i < data_len; i++) {
            if (data[i] >= 32 && data[i] < 127)
                printf("%c", data[i]);
            else
                printf(".");
        }
        printf("\n");
    }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter[] = "tcp and dst port 23";
    bpf_u_int32 net = 0;

    handle = pcap_open_live("br-90fe1db80792", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error: %s\n", errbuf);
        return 1;
    }

    pcap_compile(handle, &fp, filter, 0, net);
    pcap_setfilter(handle, &fp);
    pcap_loop(handle, -1, got_packet, NULL);
    pcap_close(handle);
    return 0;
}
