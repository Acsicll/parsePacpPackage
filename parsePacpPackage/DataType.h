#pragma once

typedef unsigned char u_int8;
typedef unsigned short u_int16;
typedef unsigned int u_int32;
typedef unsigned long long u_int64;

enum Status_t {
	error = -1,
	good = 0
};

//Pcap Header ---24B
struct pcapFileHeader_t {
	u_int32 magic;
	u_int16 version_major;
	u_int16 version_minor;
	u_int32 thiszone;
	u_int32 sigfigs;
	u_int32 snaplen;
	u_int32 linktype;
};

typedef struct time_val {
	u_int32 tv_sec;
	u_int32 tv_usec;
} time_val;

//Packet Header ---16B
struct pcap_pkthdr {
	struct time_val ts;		//捕获时间
	u_int32 caplen;			//数据帧长度
	u_int32 len;
};

//以下均为Packet Data
typedef struct FramHeader_t {
	u_int8 DstMAC[6];
	u_int8 SrcMAC[6];
	u_int8 FrameType[2];	//帧类型
} FramHeader_t;

typedef struct ip_address {
	u_int8 byte1;
	u_int8 byte2;
	u_int8 byte3;
	u_int8 byte4;
} ip_address;
typedef struct IPHeader_t {
	u_int8 Ver_HLen;
	u_int8 TOS;
	u_int16 TotalLen;
	u_int16 ID;
	u_int8 Flag;
	u_int8 Segment;
	u_int8 TTL;
	u_int8 Protocol;
	u_int16 Checksum;
	ip_address SrcIP;
	ip_address DstIP;
	//u_int32 op_pad;
} IPHeader_t;

typedef struct TCPHeader_t {
	u_int16 SrcPort;
	u_int16 DstPort;
	u_int32 seqNO;
	u_int32 AckNO;
	u_int8  tcp_hdlen_reserved;
	u_int8 Flags;
	//u_int16 headAndFlags;
	u_int16 Window;
	u_int16 Checksum;
	u_int16 UrgentPointer;
} TCPHeader_t;

