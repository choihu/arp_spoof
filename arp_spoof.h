#include <stdint.h>
#include <pcap.h>

void usage();
void print_IP(uint8_t* ip);
void print_mac(uint8_t* mac);
void parse_IP(char* ip, uint8_t* out);
int get_attacker_IP(const char* ifr, uint8_t* out);
int get_attacker_mac(char* device, uint8_t* out);
void send_arp(pcap_t* handle, int packet_type, uint8_t* src_ip, uint8_t* dest_ip, uint8_t* src_mac, uint8_t* dest_mac);
int get_mac_by_ip(pcap_t* handle, uint8_t* sender_ip, uint8_t* sender_mac);
void relay_ip_packet(pcap_t* handle, uint8_t* my_ip, uint8_t* my_mac, uint8_t* src_mac, uint8_t* dest_mac);
void prevent_arp_recovery(pcap_t* handle, uint8_t* my_ip, uint8_t* src_mac);

