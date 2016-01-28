#include "stdafx.h"

#include "pcap.h"
#include "packetutils.h"
#include "codelockpacket.h"

#define CODELOCK_PACKET_SIZE 90

#define UNRELIABLE_SIZE 40;

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

int compareCodelockPacketCode(const uint8_t* packet_start, const uint8_t* code) {

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
	InsertCrc32(packet_start, len);
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
	InsertCrc32(packet_start, len);
	write_checksum_ip(packet_start);
	InsertUDPChecksum(packet_start, len);

	// fire away
	pcap_sendpacket(adHandle, packet_start, len);
}