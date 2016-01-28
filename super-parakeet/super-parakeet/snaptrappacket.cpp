#include "stdafx.h"

#include "stdio.h"

#include "snaptrappacket.h"

// assumes a udp packet! check that first
int isSnaptrapPacket (const uint8_t* packetStart, uint32_t packetSize) {

	// must be the correct size
	if (packetSize != SNAPTRAP_PACKET_SIZE) return 0;

	// check some specific bytes
	if (packetStart[69] == 0x95 &&
		packetStart[74] == 0x02 &&
		packetStart[75] == 0xE9 &&
		packetStart[76] == 0x44 &&
		packetStart[77] == 0x53) {

		return 1;
	} else {

		return 0;
	}
}

uint32_t readSnaptrapID (const uint8_t* packetStart) {

	uint32_t id = *((uint32_t*)(packetStart + 70));

	return id;
}

void writeSnaptrapID(uint8_t* packetStart, uint32_t packetID) {

	// hnnnng
	*((uint32_t*)(packetStart + 70)) = packetID;
}