char filter_exp[] = "icmp and host 10.9.0.5 and host 10.9.0.6";char filter_exp[] = "icmp and host 10.9.0.5 and host 10.9.0.6";?#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ip.h>

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet)
{
    struct ip *iph = (struct ip *)(packet + 14);
    printf("Kaynak IP : %s\n", inet_ntoa(iph->ip_src));
    printf("Hedef IP  : %s\n\n", inet_ntoa(iph->ip_dst));
}

int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "icmp and host 10.9.0.5 and host 10.9.0.6";
    bpf_u_int32 net = 0;

    handle = pcap_open_live("br-90fe1db80792", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        printf("Hata: %s\n", errbuf);
        return 1;
    }

    pcap_compile(handle, &fp, filter_exp, 0, net);
    pcap_setfilter(handle, &fp);

    printf("Dinleniyor...\n");
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);
    return 0;
}
