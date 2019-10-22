#include <stdint.h>
#include <pcap.h>
#include <stdio.h>
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
#include <vector>
#include <pthread.h>
using namespace std;

#define REQUEST 1
#define REPLY 2

typedef struct arp_packet{
  uint8_t dest_mac[6];  //6
  uint8_t src_mac[6];   //12
  uint16_t type;        //14

  uint16_t hw_type;     //16
  uint16_t protocol_type;//18
  uint8_t hw_size;      //19
  uint8_t protocol_size;//20
  uint16_t opcode;      //22
  uint8_t src_mac2[6];  //28
  uint8_t src_ip[4];    //32
  uint8_t dest_mac2[6]; //38
  uint8_t dest_ip[4];   //42
} packet;

extern uint8_t sender_mac[10][6];
extern uint8_t target_mac[10][6];
extern uint8_t attacker_mac[6];
extern uint8_t sender_ip[10][4];
extern uint8_t target_ip[10][4];
extern uint8_t attacker_ip[4];
extern pcap_t* handle;
extern int cnt;

void usage();
void print_IP(uint8_t* ip);
void print_mac(uint8_t* mac);
void parse_IP(char* ip, uint8_t* out);
int get_attacker_IP(const char* ifr, uint8_t* out);
int get_attacker_mac(char* device, uint8_t* out);
void send_arp(pcap_t* handle, uint16_t packet_type, uint8_t* src_ip, uint8_t* dest_ip, uint8_t* src_mac, uint8_t* dest_mac);
int get_mac_by_ip(pcap_t* handle, uint8_t* sender_ip, uint8_t* sender_mac);
void relay_ip_packet(const u_char* packet, uint8_t* my_ip, uint8_t* my_mac, uint8_t* src_mac, uint8_t* dest_mac, pcap_t* handle, int length);
void prevent_arp_recovery(const u_char* packet, uint8_t* my_ip, uint8_t* src_mac, pcap_t* handle, int length);
void* arp_spoofing_cycle(void *arg);
