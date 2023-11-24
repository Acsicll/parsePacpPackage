#include<stdio.h>
#include<string.h>
#include "MyFunctions.h"
#include<iostream>

int main() {
	pcapFileHeader_t* pcapfileheader = (pcapFileHeader_t*)malloc(sizeof(pcapFileHeader_t));
	pcap_pkthdr* ptk_header = (pcap_pkthdr*)malloc(sizeof(pcap_pkthdr));
	FramHeader_t* framheader = (FramHeader_t*)malloc(sizeof(FramHeader_t));
	IPHeader_t* ipheader = (IPHeader_t*)malloc(sizeof(IPHeader_t));
	TCPHeader_t* tcpheader =(TCPHeader_t*)malloc(sizeof(TCPHeader_t));
	//std::string path;
	//if (!(std::cin >> path)) {
	//	printf("error---worng file path\n");
	//	exit(-1);
	//}
	//std::string filename = GetPcapFileName(path);
	//printf_s("filename is %s\n", filename.c_str());
	//if (!IsPcapFile(filename)) {
	//	printf("error---is not pcap file\n");
	//	exit(-1);
	//}
	char path[255] = { 0 };
	char ch = '\0';
	int index = 0;
	ch = getchar();
	while (ch != '\n') {
		path[index] = ch;
		index++;
		ch = getchar();
	}
	char* filename;
	if ((filename = GetPcapFileName(path)) != nullptr) {
		printf("%s", filename);
		printf("%s", isPcapFile(GetPcapFileName(path)) ? "\nYES\n" : "\nNO\n");
	}
	if (!strlen(filename)) {
		return -1;
	}
	FILE* fp = fopen(filename, "rb");
	if (fp == nullptr) {
		fprintf(stderr, "error---file can not open", filename);
		return -1;
	}

	u_int8 Buff[1480] = {0};
	fread(pcapfileheader, sizeof(pcapFileHeader_t), 1, fp);
	fread(ptk_header, sizeof(pcap_pkthdr), 1, fp);
	fread(framheader, sizeof(FramHeader_t), 1, fp);
	fread(ipheader, sizeof(IPHeader_t), 1, fp);
	fread(tcpheader, sizeof(TCPHeader_t), 1, fp); 
	fread(Buff, ptk_header->caplen - 54, 1, fp);

	printfPcapFileHeader(pcapfileheader);
	printf("\n");
	printfPcapHeader(ptk_header);
	printf("\n");
	printfFameInfo(framheader);
	printf("\n");
	printfIpInfo(ipheader);
	printf("\n");
	printfTcpInfo(tcpheader);
	printfInfo(Buff, ptk_header->caplen - 54,havedata);
	

	//void* ptr = (void*)malloc(sizeof(TCPHeader_t) + ptk_header->caplen - 54+1);
	//memcpy(ptr, tcpheader, sizeof(TCPHeader_t)+1);
	//memcpy(ptr, Buff, ptk_header->caplen - 54+1);

	//std::cout << std::endl << check_sum((unsigned short*)(& Buff), ipheader->TotalLen - 20);
	unsigned short buffer2[] = { 0xc0a8,0x0201,0x0006,0x004a,0x0015,0x0805,0x0000,0x1c50,0x0000,0x1b2a,
	0x5018,0x1fec,0x0000,0x0000,0x3233,0x3020,0x5573,0x6572,0x2066,0x7470,0x206c,0x6f67,0x6765,
	0x6420,0x696e,0x202c,0x2070,0x726f,0x6365,0x6564,0x0d0a};
	int n = sizeof(buffer2) / sizeof(buffer2[0]);
	auto checksum_ = checksum(buffer2, n);
	std::cout << std::endl << checksum_;
	free(pcapfileheader);
	free(ptk_header);
	free(framheader);
	free(ipheader);
	free(tcpheader);
	fclose(fp);
	return 0;
}