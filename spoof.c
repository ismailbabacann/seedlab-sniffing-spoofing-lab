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
    unsigned short result;
    for (sum = 0; len > 1; len -= 2) sum += *buf++;
    if (len == 1) sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

int main() {
    char buffer[1024];
    memset(buffer, 0, sizeof(buffer));

    struct iphdr *ip = (struct iphdr *)buffer;
    struct icmphdr *icmp = (struct icmphdr *)(buffer + sizeof(struct iphdr));

    // IP header
    ip->ihl      = 5;
    ip->version  = 4;
    ip->ttl      = 64;
    ip->protocol = IPPROTO_ICMP;
    ip->saddr    = inet_addr("10.9.0.6"); 
    ip->daddr    = inet_addr("8.8.8.8");  
    ip->tot_len  = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));

    // ICMP header
    icmp->type     = ICMP_ECHO;
    icmp->code     = 0;
    icmp->checksum = 0;
    icmp->checksum = checksum(icmp, sizeof(struct icmphdr));

    // Raw socket
    int sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sd < 0) { perror("socket error"); return 1; }

    int one = 1;
    setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ip->daddr;

    sendto(sd, buffer, ntohs(ip->tot_len), 0,
           (struct sockaddr *)&sin, sizeof(sin));

    printf("Spoofed packet sent: 10.9.0.6 --> 8.8.8.8\n");
    close(sd);
    return 0;
}
