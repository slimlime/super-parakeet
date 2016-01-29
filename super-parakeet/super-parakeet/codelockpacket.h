#pragma once

#include "stdint.h"

// this one refers to CODE SUBMISSION packets (client -> server)
int isCodelockPacket (const uint8_t* packetStart, uint32_t packetSize);

// these refer to NOTIFICATIONS OF CODE LOCK STATE CHANGE packets (server -> client)
// these return the identifier offset - but if they're not the right kind of packet, returns 0
uint32_t isCodelockUnlockedPacket( const uint8_t* packetStart, uint32_t packetSize );
uint32_t isCodelockLockedPacket( const uint8_t* packetStart, uint32_t packetSize );
uint32_t isCodelockDeniedPacket( const uint8_t* packetStart, uint32_t packetSize );

// NOTE that the following identifiers are not the same one that you get when you examine
// a client -> server code submission packet! must be matched manually
uint16_t getCodelockIDFromLockUnlockPacket( const uint8_t* packetStart, 
	uint32_t identifierOffset );

uint16_t getCodelockIDFromDeniedPacket( const uint8_t* packetStart,
	uint32_t identifierOffset );

int compareCodelockPacketCode(const uint8_t* packet_start, const uint8_t* code);

void writeCode(uint8_t* packet_start, int code);

void writeSendCodelockPacket(uint8_t* packet_start, int code, 
	uint32_t count, uint32_t len, pcap_t* adHandle);

void writeSendUnreliableCodelockPacket(uint8_t* packet_start, uint32_t len, pcap_t* adHandle);

