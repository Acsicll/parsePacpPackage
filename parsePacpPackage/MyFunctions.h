#pragma once
#include<fstream>
#include"DataType.h"
#pragma warning(disable:4996)
static bool isftppacket = false;
static std::string username;
static std::string password;
static int num = 1;


char* GetPcapFileName(char* const path) {
	if (path == nullptr) {
		return path;
	}
	else {
		char* filename = path;
		char* ptr = strrchr(path, '\\');
		if (ptr != nullptr) {
			filename = (ptr + 1);
		}
		return filename;
	}
}
bool isPcapFile(const char* filename) {
	const char strA[10] = ".pcap\0";
	const char strB[10] = ".cap\0";
	char* ret = nullptr;
	if ((ret = (char*)strstr(filename, strA)) != nullptr \
		|| (ret = (char*)strstr(filename, strA)) != nullptr)
		return true;
	else
		return false;
}

u_int32 myhtonl(const u_int32 data) {
	return	(((u_int32)data & 0xff000000 )>> 24)  |
			(((u_int32)data & 0x00ff0000 )>> 8)   |
			(((u_int32)data & 0x0000ff00 )<< 8)   |
			(((u_int32)data & 0x000000ff )<< 24);
}

u_int16 myhtons(const u_int16 data) {
	return ((data & 0xff00) >> 8) | ((data & 0x00ff) << 8);
}
void printfPcapFileHeader(pcapFileHeader_t* pfhder) {
	if (pfhder == nullptr) {
		return;
	}
	printf("\tmagic:0x%0x\n\tversion_major:%u\n\tversion_minor:%u\n"
		"\tthiszone: % d\n\tsigfigs:%u\n\tsnaplen:%u\n\tlinktype:%u\n",
		pfhder->magic, pfhder->version_major, pfhder->version_minor,
		pfhder->thiszone, pfhder->sigfigs, pfhder->snaplen, pfhder->linktype);
}

void printfPcapHeader(pcap_pkthdr* ppkhder) {
	if (ppkhder == nullptr) {
		return;
	}
	printf("\ttime_sec :%u\n\ttime_usec :%u\n\tcapturelen :%u\n\tlen :%d",
		ppkhder->ts.tv_sec, ppkhder->ts.tv_usec, ppkhder->caplen, ppkhder->len);
}

void printfFameInfo(FramHeader_t* fhd) {
	if (fhd == nullptr) {
		return;
	}
	printf("\n");
	printf("\tDstMac: (%02x:%02x:%02x:%02x:%02x:%02x)\n\tSrcMac: (%02x:%02x:%02x:%02x:%02x:%02x)\n", 
		fhd->DstMAC[0], fhd->DstMAC[1], fhd->DstMAC[2],fhd->DstMAC[3], fhd->DstMAC[4], fhd->DstMAC[5], 
		fhd->SrcMAC[0], fhd->SrcMAC[1], fhd->SrcMAC[2], fhd->SrcMAC[3],fhd->SrcMAC[4], fhd->SrcMAC[5]);
	printf("\tFrameType : 0x%02x%02x", fhd->FrameType[0], fhd->FrameType[1]);
}

void printfIpInfo(IPHeader_t* Iphd) {
	if (Iphd == nullptr) {
		return;
	}
	printf("\n");
	printf("\tVersion : %d\n", (Iphd->Ver_HLen >> 4));
	printf("\tHead Len : %d\n", (Iphd->Ver_HLen & 0x0f)*4);
	printf("\tTotal Len : %d\n", myhtons(Iphd->TotalLen));
	printf("\tDifferentiated Service Field : 0x%02x\n", Iphd->TOS);
	printf("\tIdentification : %d\n",myhtons(Iphd->ID));
	printf("\tFlags : 0x%04x\n", Iphd->Flag);
	printf("\tflagment offset : %d\n", Iphd->Segment);
	printf("\tTime to live : %d\n", Iphd->TTL);
	printf("\tProtocol : ");
	switch (Iphd->Protocol) {
	case 6:
		printf("TCP\n");
		break;
	case 17:
		printf("UPD\n");
		break;
	case 1:
		printf("ICMP\n");
		break;
	case 2:
		printf("IGMP\n");
		break;
	default:
		printf("Unknow\n");
		break;
	}
	printf("\tchecksum : %d\n", myhtons(Iphd->Checksum));
	printf("\tSrcIp : %d.%d.%d.%d\n", 
		Iphd->SrcIP.byte1, Iphd->SrcIP.byte2, Iphd->SrcIP.byte3, Iphd->SrcIP.byte4);
	printf("\tDstIp : %d.%d.%d.%d", 
		Iphd->DstIP.byte1, Iphd->DstIP.byte2, Iphd->DstIP.byte3, Iphd->DstIP.byte4);
}

void printfTcpInfo(TCPHeader_t* tcphd) {
	if (tcphd == nullptr) {
		return;
	}
	int srcPort = myhtons(tcphd->SrcPort);
	int dstPort = myhtons(tcphd->DstPort);
	printf("\tSrcPort : %d\n\tDstPort: %d",
		srcPort, dstPort);
	//std::cout << std::setw(2) << std::setfill(' ') << "{" << std::endl;
	printf(" ---{\n");
	printf("\t\t\t Service type is");
	switch ((dstPort < srcPort) ? dstPort : srcPort) {
	case 80:printf(" http.\n");
		break;
	case 21: { printf(" ftp.\n");
		isftppacket = true;
		printf("\t\t\t");
		if (srcPort == 20 || srcPort == 21) {
			printf_s(" Server connect to Client.");
		}
		else if (dstPort == 20 || dstPort == 21) {
			printf_s(" Client connect to Server.");
		}
	}
		break;
	case 23:printf(" telnet.\n");
		break;
	case 25:printf(" smtp.\n");
		break;
	case 110:printf(" pop3.\n");
		break;
	case 443:printf(" https.\n");
		break;
	default:printf(" other.\n");
		break;
	}
	//std::cout << std::endl << std::setw(23) << std::setfill(' ') << "}" << std::endl;
	printf("\n\t\t\t }\n");
	printf("\tSequence Number(raw) : %d\n", myhtonl(tcphd->seqNO));
	printf("\tAcknowledgment Number(raw) : %d\n", myhtonl(tcphd->AckNO));
	printf("\tHeader Length : %d\n", (tcphd->tcp_hdlen_reserved >> 4) * 4);
	printf("\tFlags : 0x%02x", tcphd->Flags);
	printf(" ----{\n");
	//std::cout << std::setw(2) << std::setfill(' ') << "{" << std::endl;
	printf("\t\t\t");
	if (tcphd->Flags & 0x08)  printf(" -[PSH]-");
	if (tcphd->Flags & 0x10)  printf(" -[ACK]-");
	if (tcphd->Flags & 0x02)  printf(" -[SYN]-");
	if (tcphd->Flags & 0x20)  printf(" -[URG]-");
	if (tcphd->Flags & 0x01)  printf(" -[FIN]-");
	if (tcphd->Flags & 0x04)  printf(" -[RST]-");
	//std::cout << std::endl << std::setw(22) << std::setfill(' ') << "}"<<std::endl;
	printf("\n\t\t\t }\n");
	printf("\tWindows : %d\n", myhtons(tcphd->Window));
	printf("\tCheckSum : %d\n", myhtons(tcphd->Checksum));
	printf("\tUrgent Point : %d\n", myhtons(tcphd->UrgentPointer));
}
bool havedata(int len){
	return (len > 0? true : false);
}
void printfInfo(u_int8* data,int len,bool (*ptrfunc)(int)) {
	std::string com;//设定接受的状态
	if (data != nullptr) {
		for (auto i = 0; i < 4; i++) {
			com += (char)data[i];
		}
	}
	else {
		return;
	}
	if (isftppacket && ptrfunc(len)) {
		std::string info;
		bool have_username = false;
		bool have_password = false;
		bool is_needout_info = false;
		if (com == "USER") {
			if (!username.length()) {
				username.clear();	//防止user数据不干净
			}
			for (auto i =  5; data[i] != 13; i++) {	//u_int8 = 13为回车字符
				username += (char)data[i];
			}
			info = "Input username!";
			have_username = true;
		}
		else if (com == "PASS") {
			if (!password.length()) {
				password.clear();
			}
			for (auto i =  5; data[i] != 13; i++) {
				password += (char)data[i];
			}
			info = "Input password!";
			have_password = true;
		}
		else if (com == "230 " || com == "530 " || com == "220 " || com == "331 " || com == "221 ") {
			for (auto i = 0; data[i] != 13; i++) {
				info += (char)data[i];
			}
			is_needout_info = true;
		}
		printf("\t\t\t");
		if (have_username && have_password) {
			printf_s("user:%s, password:%s\n", username.c_str(), password.c_str());
		}
		if (is_needout_info) {
			printf_s("info:%s", info.c_str());
		}
		printf("\n");
	}
}
unsigned short checksum(unsigned short* buf, int nword)
{
	unsigned long sum;
	for (sum = 0; nword > 0; nword--)
	{
		sum += *buf++;
		
	}
	//auto t1 = sum, t2 = sum;
	//sum = (t1 & 0xffff0000) >> 16 + (t2 & 0x0000ffff);

	return (sum ^ 0xffff);
}

u_int32 ipaddrTou32(ip_address ip) {
	return (((ip.byte1 << 24) & 0xff000000) |
		((ip.byte2 << 16) & 0x00ff0000) |
		((ip.byte3 << 8) & 0x0000ff00) |
		(ip.byte4));
}


static uint16_t checksum_compute(void* data, int protocol, int len, u_int32 sip, u_int32 dip)
{
	int sum, oddbyte, phlen;
	uint16_t* ptr;

	struct {
		u_int32 sip;
		u_int32 dip;
		uint8_t zero;
		uint8_t prot;
		uint16_t len;
	} pseudo_hdr = { sip, dip, 0, protocol , myhtons(len & 0xffff) };

	sum = 0;

	phlen = sizeof(pseudo_hdr);
	ptr = (uint16_t*)&pseudo_hdr;

	while (phlen > 1) {
		sum += *ptr++;
		phlen -= 2;
	}

	ptr = (uint16_t*)data;

	while (len > 1) {
		sum += *ptr++;
		len -= 2;
	}

	if (len == 1) {
		oddbyte = 0;
		((uint8_t*)&oddbyte)[0] = *(uint8_t*)ptr;
		((uint8_t*)&oddbyte)[1] = 0;
		sum += oddbyte;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	sum = ~sum & 0xffff;

	return sum;
}


