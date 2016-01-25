// super-parakeet.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#include <pcap.h>
#include <iostream>
#include <vector>

constexpr char* FilterString = "dst 115.70.89.65";

// Adapter handle.
pcap_t*			adHandle = nullptr;


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
		&& *( pkt_data + 77 ) == 0xBD )
	{
		// Local time and size.
		localTvSec = header->ts.tv_sec;
		localtime_s( &ltime, &localTvSec );
		strftime( timeStr, sizeof( timeStr ), "%H:%M:%S", &ltime );
		std::cout << timeStr << ", " << header->ts.tv_usec << " len: "
			<< header->len << std::endl;

		// Print out the entered code.
		std::cout << "Entered code: " << *( pkt_data + 82 )
			<< *( pkt_data + 83 )
			<< *( pkt_data + 84 )
			<< *( pkt_data + 85 ) << std::endl;
	}

	// Copy the packet, modified the code number, and send our new copy.
	if ( adHandle != nullptr )
	{
		std::vector<u_char> copyPacket = std::vector<u_char>( header->len );
		std::copy( pkt_data, pkt_data + header->len, copyPacket.begin() );

		// Just use this to test.
		copyPacket[82] = '1';
		copyPacket[83] = '2';
		copyPacket[84] = '3';
		copyPacket[85] = '3';

		// Send the copied packet.
		pcap_sendpacket( adHandle, copyPacket.data(), header->len );
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

