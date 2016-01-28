#pragma once

#include "stdint.h"

// get a little endian 32 bit uint from a byte array

// bit wrangling, endian conversion etc
void Swap32(uint32_t* source, uint32_t* destination);
void Swap24(uint8_t* source, uint8_t* destination);
void Swap16(uint16_t* source, uint16_t* destination);

// copy sequence number between packets
void copy_sequence_number(const uint8_t* packet_start_src, uint8_t* packet_start_dst,
	uint32_t seq_data_offset);

// increments a 24-bit little endian number in the packet, given an offset from the data
void increment_sequence_number(uint8_t* packet_start, int seq_data_offset, int increment);

// calculates and writes checksums - use just before sending packet
uint16_t write_checksum_ip(uint8_t* packet);
void InsertCrc32(uint8_t* packet_start, size_t len);
void InsertUDPChecksum(uint8_t* data, uint32_t len);

// kinda made redundant by header->len
uint32_t getUDPPacketSize(const uint8_t* packetStart);
uint32_t getUDPLength(const uint8_t* packetStart);

// don't call these - use write_checksum_ip, InsertCrc32, and InsertUDPChecksum
// respectively (and make sure you do it in that order)
uint16_t checksum_ip(const uint16_t* ipheader);
uint16_t udp_sum_calc(uint16_t len_udp, uint16_t src_addr[], uint16_t dest_addr[], int padding, uint16_t buff[]);
uint32_t crc32(uint32_t crc, const void *buf, size_t size);