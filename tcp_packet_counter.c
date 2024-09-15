#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h> // Работа с IP-адресами
#include <netinet/ip.h> // Структуры для IP-заголовков
#include <netinet/tcp.h> // Структуры для TCP-заголовков

// Инструкция
void usage(const char *progname) {
    printf("Usage: %s <pcap file> [--srcaddr <source IP>] [--dstaddr <destination IP>] [--srcport <source port>] [--dstport <destination port>]\n", progname); 
}

int main(int argc, char *argv[]) {
    // Проверка пути к файлу
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    // Инициализация переменных для аргументов командной строки
    char *pcap_file = argv[1];
    char *src_ip = NULL, *dst_ip = NULL;
    int src_port = -1, dst_port = -1;

    // Обработка аргументов командной строки
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--srcaddr") == 0 && i + 1 < argc) {
            src_ip = argv[++i];
        } else if (strcmp(argv[i], "--dstaddr") == 0 && i + 1 < argc) {
            dst_ip = argv[++i];
        } else if (strcmp(argv[i], "--srcport") == 0 && i + 1 < argc) {
            src_port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--dstport") == 0 && i + 1 < argc) {
            dst_port = atoi(argv[++i]);
        } else {
            usage(argv[0]);
            return 1;
        }
    }

    // Открытие pcap-файла для чтения
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(pcap_file, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open pcap file %s: %s\n", pcap_file, errbuf);
        return 1;
    }

    struct pcap_pkthdr *header; // Заголовок пакета
    const u_char *packet; // Данные пакета
    int total_packets = 0, tcp_packets = 0, filtered_tcp_packets = 0;

    // Чтение пакетов из pcap-файла
    while (pcap_next_ex(handle, &header, &packet) >= 0) {
        total_packets++; 
        //printf("Processing packet %d\n", total_packets);

        // Извлечение IP-заголовка (ethernet)
        struct ip *ip_header = (struct ip *)(packet + 14);
        if (ip_header->ip_p == IPPROTO_TCP) { // Проверка, является ли пакет TCP
            tcp_packets++; 

            // Извлечение TCP-заголовка
            struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + ip_header->ip_hl * 4);
            char src_ip_str[INET_ADDRSTRLEN], dst_ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(ip_header->ip_src), src_ip_str, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip_str, INET_ADDRSTRLEN);

            int src_port_packet = ntohs(tcp_header->source);
            int dst_port_packet = ntohs(tcp_header->dest);

	//printf("Source IP: %s, Destination IP: %s\n", src_ip_str, dst_ip_str);
	//printf("Source Port: %d, Destination Port: %d\n", src_port_packet, dst_port_packet);

            // Проверка фильтров
            if ((src_ip == NULL || strcmp(src_ip, src_ip_str) == 0) &&
                (dst_ip == NULL || strcmp(dst_ip, dst_ip_str) == 0) &&
                (src_port == -1 || src_port == src_port_packet) &&
                (dst_port == -1 || dst_port == dst_port_packet)) {
                filtered_tcp_packets++;
            }
        }
    }

    pcap_close(handle);

    // Вывод результатов
    printf("Total packets: %d\n", total_packets);
    printf("Total TCP packets: %d\n", tcp_packets);
    printf("Filtered TCP packets: %d\n", filtered_tcp_packets);


    return 0;
}
