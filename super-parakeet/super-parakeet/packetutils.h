#pragma once

#include "stdint.h"

void Swap32 (uint32_t* source, uint32_t* destination);
void Swap24 (uint8_t* source, uint8_t* destination);
void Swap16(uint16_t* source, uint16_t* destination);
void copy_sequence_number(const uint8_t* packet_start_src, uint8_t* packet_start_dst,
	uint32_t seq_data_offset);
void increment_sequence_number (uint8_t* packet_start, int seq_data_offset, int increment);
uint16_t write_checksum_ip(uint8_t* packet);
void InsertCrc32(uint8_t* data, size_t len);
void InsertUDPChecksum(uint8_t* data, uint32_t len);

uint32_t getUDPPacketSize(const uint8_t* packetStart);
uint32_t getUDPLength(const uint8_t* packetStart);

// INTERNAL
uint16_t checksum_ip(const uint16_t* ipheader);
uint16_t udp_sum_calc(uint16_t len_udp, uint16_t src_addr[], uint16_t dest_addr[], int padding, uint16_t buff[]);
uint32_t crc32(uint32_t crc, const void *buf, size_t size);