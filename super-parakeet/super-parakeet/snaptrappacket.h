#pragma once

#include "stdint.h"

#define SNAPTRAP_PACKET_SIZE 82

int isSnaptrapPacket (const uint8_t* packetStart, uint32_t packetSize);
uint32_t readSnaptrapID (const uint8_t* packetStart);
void writeSnaptrapID (uint8_t* packetStart, uint32_t id);