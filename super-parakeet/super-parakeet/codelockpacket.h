#pragma once

#include "stdint.h"

int isCodelockPacket (const uint8_t* packetStart, uint32_t packetSize);
int isCodelockUnlockedPacket( const uint8_t* packetStart, uint32_t packetSize );
int isCodelockLockedPacket( const uint8_t* packetStart, uint32_t packetSize );

int compareCodelockPacketCode(const uint8_t* packet_start, const uint8_t* code);

void writeCode(uint8_t* packet_start, int code);

void writeSendCodelockPacket(uint8_t* packet_start, int code, 
	uint32_t count, uint32_t len, pcap_t* adHandle);

void writeSendUnreliableCodelockPacket(uint8_t* packet_start, uint32_t len, pcap_t* adHandle);