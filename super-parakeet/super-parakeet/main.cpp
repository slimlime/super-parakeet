// super-parakeet.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#include <pcap.h>
#include <iostream>
#include <vector>
#include <stdint.h>
#include <thread>

#include "stdio.h"

#define DATA_SIZE_FULL 90
#define PACKET_DATA_START 42
#define IP_HEADER_LEN 20


void Swap32( uint32_t* source, uint32_t* destination )
{
	auto source8	  = ( uint8_t* )source;
	auto destination8 = ( uint8_t* )destination;
	destination8[0] = source8[3];
	destination8[1] = source8[2];
	destination8[2] = source8[1];
	destination8[3] = source8[0];
}


void Swap24( uint8_t* source, uint8_t* destination )
{
	destination[0] = source[2];
	destination[2] = source[0];
}


void Swap16( uint16_t* source, uint16_t* destination )
{
	auto source8		 = ( uint8_t* )source;
	auto destination8	 = ( uint8_t* )destination;
	destination8[0] = source8[1];
	destination8[1] = source8[0];
}


void increment_sequence_number( uint8_t* packet_start, int seq_data_offset, int increment ) {

	uint32_t seq = *( ( uint32_t* )( packet_start + PACKET_DATA_START + seq_data_offset ) );

	// zero out the last bits
	seq &= 0x00ffffff;

	// add the increment
	seq += increment;

	// stick it back in
	packet_start[PACKET_DATA_START + seq_data_offset] = ( uint8_t )( seq & 0x000000ff );
	packet_start[PACKET_DATA_START + seq_data_offset + 1] = ( uint8_t )( ( seq & 0x0000ff00 ) >> 8 );
	packet_start[PACKET_DATA_START + seq_data_offset + 2] = ( uint8_t )( ( seq & 0x00ff0000 ) >> 16 );
}



uint16_t checksum_ip( const uint16_t* ipheader );
uint16_t udp_sum_calc( uint16_t len_udp, uint16_t src_addr[], uint16_t dest_addr[], int padding, uint16_t buff[] );

uint16_t write_checksum_ip( uint8_t* packet ) {

	int i = 0;

	// recast
	uint16_t header_16[10];

	printf( "\n" );
	// swap
	uint16_t tmp;
	for ( i = 0; i < IP_HEADER_LEN / 2; i++ ) {
		tmp = *( uint16_t* )( packet + 14 + 2 * i );
		header_16[i] = ( tmp >> 8 ) | ( tmp << 8 );
		printf( "%x ", header_16[i] );
	}

	uint16_t cs_ip = checksum_ip( header_16 );

	// write it in
	packet[25] = ( uint8_t )( cs_ip & 0x00ff );
	packet[24] = ( uint8_t )( cs_ip >> 8 );

	return cs_ip;
}

// checksum for the ip header
uint16_t checksum_ip( const uint16_t* ipheader ) {

	unsigned long sum = 0;

	unsigned i;
	for ( i = 0; i < 10; i++ ) {
		if ( i != 5 ) { sum += ( unsigned long )( ipheader[i] ); }
		if ( sum & 0x80000000 ) { sum = ( sum & 0xffff ) + ( sum >> 16 ); }
	}

	while ( sum >> 16 ) {
		sum = ( sum & 0xffff ) + ( sum >> 16 );
	}

	return ( ~sum );
}



uint16_t udp_sum_calc( uint16_t len_udp, uint16_t src_addr[], uint16_t dest_addr[], int padding, uint16_t buff[] )
{

	uint16_t prot_udp = 17;
	uint16_t padd = 0;
	uint16_t word16;
	uint32_t sum;

	int i = 0;

	// Find out if the length of data is even or odd number. If odd,
	// add a padding byte = 0 at the end of packet
	if ( padding ) {
		padd = 1;
		buff[len_udp] = 0;
	}

	//initialize sum to zero
	sum = 0;

	// make 16 bit words out of every two adjacent 8 bit words and
	// calculate the sum of all 16 vit words
	for ( i = 0; i < len_udp + padd; i += 2 ) {
		word16 = buff[i / 2];
		// word16 = (word16 >> 8) | (word16 << 8);
		sum += ( uint32_t )word16;
	}
	// add the UDP pseudo header which contains the IP source and destinationn addresses
	for ( i = 0; i < 4; i += 2 ) {
		// word16 =((src_addr[i]<<8)&0xff00)+(src_addr[i+1]&0x00ff);
		word16 = src_addr[i / 2];
		// word16 = (word16 >> 8) | (word16 << 8);
		sum += word16;
	}
	for ( i = 0; i<4; i = i + 2 ) {
		// word16 =((dest_addr[i]<<8)&0xff00)+(dest_addr[i+1]&0x00ff);
		word16 = dest_addr[i / 2];
		// word16 = (word16 >> 8) | (word16 << 8);
		sum += word16;
	}
	// the protocol number and the length of the UDP packet
	sum = sum + prot_udp + len_udp;

	// keep only the last 16 bits of the 32 bit calculated sum and add the carries
	while ( sum >> 16 )
		sum = ( sum & 0xffff ) + ( sum >> 16 );

	// Take the one's complement of sum
	sum = ~sum;

	return ( ( uint16_t )sum );
}

constexpr char* FilterString = "dst 115.70.89.65";

// Adapter handle.
pcap_t*			adHandle = nullptr;


static uint32_t crc32_tab[] = {
	0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f,
	0xe963a535, 0x9e6495a3,	0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
	0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2,
	0xf3b97148, 0x84be41de,	0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
	0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec,	0x14015c4f, 0x63066cd9,
	0xfa0f3d63, 0x8d080df5,	0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
	0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,	0x35b5a8fa, 0x42b2986c,
	0xdbbbc9d6, 0xacbcf940,	0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
	0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423,
	0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
	0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,	0x76dc4190, 0x01db7106,
	0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
	0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d,
	0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
	0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
	0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
	0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7,
	0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
	0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa,
	0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
	0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81,
	0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
	0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84,
	0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
	0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
	0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
	0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8, 0xa1d1937e,
	0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
	0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55,
	0x316e8eef, 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
	0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28,
	0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
	0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f,
	0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
	0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
	0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
	0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69,
	0x616bffd3, 0x166ccf45, 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
	0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc,
	0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
	0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693,
	0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
	0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
};

uint32_t crc32( uint32_t crc, const void *buf, size_t size )
{
	const uint8_t *p;

	p = reinterpret_cast<const uint8_t*>( buf );
	crc = crc ^ ~0U;

	while ( size-- )
		crc = crc32_tab[( crc ^ *p++ ) & 0xFF] ^ ( crc >> 8 );

	return crc ^ ~0U;
}


void InsertCrc32( uint8_t* data, size_t len )
{
	auto crc = crc32( 0x00000000, data + 42,
		len - ( 42 + 4 ) );

	uint32_t reversed = 0;
	uint8_t* crcPtr = reinterpret_cast<uint8_t*>( &crc );
	uint8_t* reversedPtr = reinterpret_cast<uint8_t*>( &reversed );
	reversedPtr[0] = crcPtr[0];
	reversedPtr[1] = crcPtr[1];
	reversedPtr[2] = crcPtr[2];
	reversedPtr[3] = crcPtr[3];

	// Copy new CRC over.
	data[86] = reversedPtr[0];
	data[87] = reversedPtr[1];
	data[88] = reversedPtr[2];
	data[89] = reversedPtr[3];
}


typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned long u32;


u16 udp_sum_calc( u16 len_udp, u8* src_addr, u8* dest_addr, bool padding, u8 buff[] )
{
	u16 prot_udp = 17;
	u16 padd = 0;
	u16 word16;
	u32 sum;
	u32 i;

	// Find out if the length of data is even or odd number. If odd,
	// add a padding byte = 0 at the end of packet
	if ( ( padding & 1 ) == 1 ) {
		padd = 1;
		buff[len_udp] = 0;
	}

	//initialize sum to zero
	sum = 0;

	// make 16 bit words out of every two adjacent 8 bit words and 
	// calculate the sum of all 16 vit words
	for ( i = 0; i<len_udp + padd; i = i + 2 ) {
		word16 = ( ( buff[i] << 8 ) & 0xFF00 ) + ( buff[i + 1] & 0xFF );
		sum = sum + ( unsigned long )word16;
	}
	// add the UDP pseudo header which contains the IP source and destinationn addresses
	for ( i = 0; i<4; i = i + 2 ) {
		word16 = ( ( src_addr[i] << 8 ) & 0xFF00 ) + ( src_addr[i + 1] & 0xFF );
		sum = sum + word16;
	}
	for ( i = 0; i<4; i = i + 2 ) {
		word16 = ( ( dest_addr[i] << 8 ) & 0xFF00 ) + ( dest_addr[i + 1] & 0xFF );
		sum = sum + word16;
	}
	// the protocol number and the length of the UDP packet
	sum = sum + prot_udp + len_udp;

	// keep only the last 16 bits of the 32 bit calculated sum and add the carries
	while ( sum >> 16 )
		sum = ( sum & 0xFFFF ) + ( sum >> 16 );

	// Take the one's complement of sum
	sum = ~sum;

	return ( ( u16 )sum );
}


void InsertUDPChecksum( uint8_t* data )
{
	data[40] = 0;
	data[41] = 0;
	uint16_t* udp_length_tmp = ( uint16_t* )( data + 38 );
	uint16_t udp_length = ( udp_length_tmp[0] >> 8 ) | ( udp_length_tmp[0] << 8 );

	auto checksum = udp_sum_calc( udp_length, ( &( data[26] ) ),
		( &( data[30] ) ), false, ( &( data[34] ) ) );

	*( ( uint16_t* )( data + 40 ) ) = ( checksum >> 8 ) | ( checksum << 8 );
}


void SendPacket( const pcap_pkthdr* header, const u_char* pkt_data, int i,
					int packetCount )
{
	std::vector<u_char> copyPacket = std::vector<u_char>( header->len );
	std::copy( pkt_data, pkt_data + header->len, copyPacket.begin() );

	int code = i;
	copyPacket[82] = '0' + ( code / 1000 );

	code %= 1000;
	copyPacket[83] = '0' + ( code / 100 );

	code %= 100;
	copyPacket[84] = '0' + ( code / 10 );

	code %= 10;
	copyPacket[85] = '0' + ( code );

	// Increment sequence numbers.
	increment_sequence_number( copyPacket.data(), 5, 100 + packetCount );
	increment_sequence_number( copyPacket.data(), 11, 100 + packetCount );
	increment_sequence_number( copyPacket.data(), 14, 100 + packetCount );

	InsertCrc32( copyPacket.data(), header->len );
	write_checksum_ip( copyPacket.data() );
	InsertUDPChecksum( copyPacket.data() );

	// Send the copied packet.
	pcap_sendpacket( adHandle, copyPacket.data(), header->len );
}


void PacketHandler( u_char* param, const pcap_pkthdr* header,
	const u_char* pkt_data )
{
	tm		ltime;
	char	timeStr[16];
	time_t	localTvSec;

	// Only accept RPC packets.
	if ( *( pkt_data + 69 ) == 0x95
		&& *( pkt_data + 74 ) == 0xF7
		&& *( pkt_data + 75 ) == 0xE6
		&& *( pkt_data + 76 ) == 0xBA	
		&& *( pkt_data + 77 ) == 0xBD
		&& *( pkt_data + 82 ) == '7'
		&& *( pkt_data + 83 ) == '7' 
		&& *( pkt_data + 84 ) == '7' 
		&& *( pkt_data + 85 ) == '7' )
	{
		// Local time and size.
		localTvSec = header->ts.tv_sec;
		localtime_s( &ltime, &localTvSec );
		strftime( timeStr, sizeof( timeStr ), "%H:%M:%S", &ltime );
		std::cout << timeStr << ", " << header->ts.tv_usec << " len: "
			<< header->len << std::endl;

		auto originalCrc = 0;
		originalCrc		 |= ( ( uint32_t )( *( pkt_data + 86 ) ) ) << 24;
		originalCrc	     |= ( ( uint32_t )( *( pkt_data + 87 ) ) ) << 16;
		originalCrc		 |= ( ( uint32_t )( *( pkt_data + 88 ) ) ) << 8;
		originalCrc		 |= ( ( uint32_t )( *( pkt_data + 89 ) ) );

		std::cout << "Original CRC: " << std::hex << originalCrc << std::endl;

		// Copy the packet, modify the code number, and send our new copy.
		if ( adHandle != nullptr )
		{
			int packetCount = 0;
			for( int i = 0; i < 10000; ++i )
			{
				if( i == 7777 )
				{
					continue;
				}
				SendPacket( header, pkt_data, i, 600 + packetCount );
				SendPacket( header, pkt_data, i, 600 + packetCount );
				packetCount += 1;
			}
		}
	}
}


int main()
{
	pcap_if_t*	allDevs;
	char		errorBuffer[PCAP_ERRBUF_SIZE];

	// Find all available devices.
	if ( pcap_findalldevs_ex( PCAP_SRC_IF_STRING, nullptr, &allDevs,
		errorBuffer ) )
	{
		std::cout << "Error in pcap_finalldevs_ex: " << errorBuffer
			<< std::endl;
		return -1;
	}

	int i = 0;
	for ( auto* d = allDevs; d != nullptr; d = d->next, ++i )
	{
		std::cout << i << ". " << d->name;
		if ( d->description != nullptr )
		{
			std::cout << d->description << std::endl;
		}
		else
		{
			std::cout << "No description available." << std::endl;
		}
	}

	if ( i == 0 )
	{
		std::cout << "No interfaces found! Make sure WinPcap is installed."
			<< std::endl;
		return -1;
	}

	// Choose a device.
	int chosen = 0;
	std::cout << "Enter the interface number( 1 - " << i << " ): ";
	std::cin >> chosen;

	if ( chosen < 1 || chosen > i )
	{
		std::cout << "Interface number out of range." << std::endl;
		pcap_freealldevs( allDevs );
		return -1;
	}

	// Move through the device list until we get to the chosen one.
	i = 0;
	auto* d = allDevs;
	for ( d = allDevs; i < chosen - 1; d = d->next, ++i )
	{
	}

	// Open the device.
	adHandle = pcap_open( d->name, 65536,
		PCAP_OPENFLAG_PROMISCUOUS, 1000, nullptr, errorBuffer );
	if ( adHandle == nullptr )
	{
		std::cout << "Unable to open the adapter. " << d->name
			<< "is not supported by WinPcap" << std::endl;
		pcap_freealldevs( allDevs );
		return -1;
	}

	std::cout << "Listening on " << d->name << std::endl;
	pcap_freealldevs( allDevs );


	bpf_u_int32 mask = 0;
	if ( d->addresses != nullptr )
	{
		mask =
			( ( sockaddr_in* )( d->addresses->netmask ) )->sin_addr.S_un.S_addr;
	}
	else
	{
		mask = 0xFFFFFFFF;
	}

	// Compile and set the packet filter.
	bpf_program code;
	if ( pcap_compile( adHandle, &code, FilterString, 1, mask ) < 0 )
	{
		std::cout << "Unable to compile the packet filter. Check the syntax"
			<< std::endl;
		return -1;
	}

	if ( pcap_setfilter( adHandle, &code ) < 0 )
	{
		std::cout << "Error setting the filter." << std::endl;
		return -1;
	}

	// Pcap outgoing packet callback.
	pcap_loop( adHandle, 0, PacketHandler, nullptr );

	return 0;
}

