#include "stdafx.h"

#include "pcap.h"
#include "packetutils.h"
#include "codelockpacket.h"

#define CODELOCK_PACKET_SIZE 90

// what?
#define UNRELIABLE_SIZE 40

// header index of the LAST BYTE OF THE RAKNET HEADER
#define RAKNET_HEADER_END 59

int isCodelockPacket(const uint8_t* packetStart, uint32_t packetSize) {

	// must have the correct size
	if (packetSize != CODELOCK_PACKET_SIZE) return 0;

	// check specific bytes
	if (packetStart[69] == 0x95 &&
		packetStart[74] == 0xF7 &&
		packetStart[75] == 0xE6 &&
		packetStart[76] == 0xBA &&
		packetStart[77] == 0xBD) {

		return 1;
	} else {

		return 0;
	}
}

uint32_t isCodelockUnlockedPacket( const uint8_t* packetStart, uint32_t packetSize )
{
	// TODO: Make this work. nah get fukd

	// if this packet doesn't contain our sweet sweet magic numbers, no dice:

	uint8_t lockUnlockPacketIdentifier[] = { 0x01, 0xa0, 0x06, 0x00 };
	int hasFoundPacketIdentifier = 0;
	uint32_t packetIdentifierOffset = 0;

	for (unsigned i = RAKNET_HEADER_END + 1; i < packetSize - 3; i++) {

		if (lockUnlockPacketIdentifier[0] == packetStart[i] &&
			lockUnlockPacketIdentifier[1] == packetStart[i + 1] &&
			lockUnlockPacketIdentifier[2] == packetStart[i + 2] &&
			lockUnlockPacketIdentifier[3] == packetStart[i + 3]) {

			hasFoundPacketIdentifier = 1;
			packetIdentifierOffset = i;
			break;
		}
	}

	if (!hasFoundPacketIdentifier) return 0;

	// now we need to check to see whether this was a lock or an unlock message
	uint8_t lockOrUnlock = packetStart[packetIdentifierOffset - 17];

	// if it's a lock packet (0x01)
	if (lockOrUnlock == 0x10) return 0;

	// otherwise it's an unlock!
	return packetIdentifierOffset;
}

uint32_t isCodelockLockedPacket( const uint8_t* packetStart, uint32_t packetSize )
{
	// TODO: Make this work. yer

	// if this packet doesn't contain our sweet sweet magic numbers, no dice:

	uint8_t lockUnlockPacketIdentifier[] = { 0x01, 0xa0, 0x06, 0x00 };
	int hasFoundPacketIdentifier = 0;
	uint32_t packetIdentifierOffset = 0;

	for (unsigned i = RAKNET_HEADER_END + 1; i < packetSize - 3; i++) {

		if (lockUnlockPacketIdentifier[0] == packetStart[i] &&
			lockUnlockPacketIdentifier[1] == packetStart[i + 1] &&
			lockUnlockPacketIdentifier[2] == packetStart[i + 2] &&
			lockUnlockPacketIdentifier[3] == packetStart[i + 3]) {

			hasFoundPacketIdentifier = 1;
			packetIdentifierOffset = i;
			break;
		}
	}

	if (!hasFoundPacketIdentifier) return 0;

	// now we need to check to see whether this was a lock or an unlock message
	uint8_t lockOrUnlock = packetStart[packetIdentifierOffset - 17];

	// if it's a lock packet (0x01)
	if (lockOrUnlock == 0x10) return packetIdentifierOffset;

	// otherwise it's not!
	return 0;
}

uint32_t isCodelockDeniedPacket(const uint8_t* packetStart, uint32_t packetSize) {

	// way more magic numbers this time!

	// there probably exists a shorter identifier, but this seems to work
	uint8_t deniedPacketIdentifier[] = { 0x2a, 0x0f, 0x0d, 0x00, 0x00, 0x00, 0x00,
		0x15, 0x00, 0x00, 0x00, 0x00, 0x1d, 0x00, 0x00, 0x80, 0x3f, 0x35, 0x00, 0x00, 0x00 };

	uint32_t identifierLen = 21;

	int hasFoundPacketIdentifier = 0;
	uint32_t packetIdentifierOffset = 0;

	for (unsigned i = RAKNET_HEADER_END + 1; i < packetSize - identifierLen + 1; i++) {

		int cond = 1;
		for (unsigned j = 0; j < identifierLen; j++) {

			cond = cond && deniedPacketIdentifier[j] == packetStart[i + j];
			if (!cond) break;
		}

		if (hasFoundPacketIdentifier = cond) break;
		packetIdentifierOffset = i;
	}

	// didn't find it 
	if (!hasFoundPacketIdentifier) return 0;

	// otherwise ...
	return packetIdentifierOffset;
}

uint16_t getCodelockIDFromLockUnlockPacket(const uint8_t* packetStart,
	uint32_t identifierOffset) {

	// why does this even need to be a function
	return *((uint16_t*)(packetStart + identifierOffset - 11));
}

uint16_t getCodelockIDFromDeniedPacket(const uint8_t* packetStart,
	uint32_t identifierOffset) {

	// yerrr ;~~))
	return *((uint16_t*)(packetStart + identifierOffset + 23));
}

int compareCodelockPacketCode(const uint8_t* packet_start, const uint8_t* code) {

	// should be easier than this? just compare uint32_t?
	return (packet_start[85] == code[0] &&
		packet_start[84] == code[1] &&
		packet_start[83] == code[2] &&
		packet_start[82] == code[3]);
}

void writeCode(uint8_t* packet_start, int code) {

	packet_start[82] = '0' + (code / 1000);

	code %= 1000;
	packet_start[83] = '0' + (code / 100);

	code %= 100;
	packet_start[84] = '0' + (code / 10);

	code %= 10;
	packet_start[85] = '0' + (code);
}

void writeSendCodelockPacket(uint8_t* packet_start, int code,
	uint32_t count, uint32_t len, pcap_t* adHandle) {

	// write the current code
	writeCode(packet_start, code);

	// seq numbers
	increment_sequence_number(packet_start, 5, count);
	increment_sequence_number(packet_start, 11, count);
	increment_sequence_number(packet_start, 14, count);

	// checksums
	write_checksum_ip(packet_start);
	InsertUDPChecksum(packet_start, len);

	// fire away
	pcap_sendpacket(adHandle, packet_start, len);
}

// testing - copy and write an unreliable packet, then send it
void writeSendUnreliableCodelockPacket(uint8_t* packet_start, uint32_t len, pcap_t* adHandle) {
	
	// change the length fields in the headers before doing the checksums

	// ip len field
	uint16_t lenOriginal; Swap16( (uint16_t*)(packet_start + 16), &lenOriginal );
	uint16_t lenNew = lenOriginal - 7;

	// write the new length back in
	Swap16( &lenNew, (uint16_t*)(packet_start + 16) );
	//*((uint16_t*)(packet_start + 16)) = lenNew;

	// udp len field
	Swap16((uint16_t*)(packet_start + 38), &lenOriginal);
	lenNew = lenOriginal - 7;

	// write the new length back in
	Swap16(&lenNew, (uint16_t*)(packet_start + 38));
	//*((uint16_t*)(packet_start + 38)) = lenNew;

	// checksums
	write_checksum_ip(packet_start);
	InsertUDPChecksum(packet_start, len);

	// fire away
	pcap_sendpacket(adHandle, packet_start, len);
}