// super-parakeet.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#include <pcap.h>
#include <iostream>
#include <vector>
#include <stdint.h>
#include <thread>
#include <set>
#include <atomic>

#include "stdio.h"

#include "packetutils.h"
#include "codelockpacket.h"
#include "snaptrappacket.h"


// if something's not working check this first!
constexpr char* FilterString = "(dst 103.13.101.191 || src 103.13.101.191) && proto 17";

// Adapter handle.
pcap_t*			adHandle	= nullptr;

std::thread			sendThread;
std::atomic_int32_t codeFailureCount;
std::atomic_bool	isSending;
std::atomic_bool	isCodeFound;

// struct storing state for snaptrap field system
struct {

	// set of snaptrap IDs that'll be armed
	std::set<uint32_t> snaptrapIDs;

	// the last snaptrap packet data received - get's copied and sent
	// (modified first) for each snaptrap when the remote arming is triggered
	uint8_t snaptrapPacketLast[SNAPTRAP_PACKET_SIZE];

} snaptrapFieldState;


void DelayPrintFinalCode() {

	std::this_thread::sleep_for(std::chrono::milliseconds(1000));

	// after waiting for a bit, let's see what the count is
	printf("got that sweet sweet code: %i\n", codeFailureCount.load());
}

void SendCodeLockPackets( pcap_t* adHandle, std::vector<u_char> originalPacket )
{
	printf( "Firing in 10 seconds ...\n" );

	// delay to allow for suicide (less suspicious than getting killed by a code lock)
	std::this_thread::sleep_for( std::chrono::milliseconds( 10000 ) );

	// allocate copy outside of loop - we won't need as much memory, because we're
	// removing certain bytes to make it fit the raknet UNRELIABLE packet type
	// but it's easier to copy the whole thing then erase that bit out
	std::vector<u_char> copyPacket = std::vector<u_char>( originalPacket.size() );

	// length of new, shorter packet
	uint32_t lenNew = originalPacket.size() - 7;

	if ( adHandle != nullptr ) {

		for ( int i = 0; i < 20000; i++ ) {

			int code = i % 10000;

			if ( code == 7777 ) continue;

			// we've found the code, so stop sending packets
			if(isCodeFound.load()) {

				isSending.store( false );
				return;
			}

			// resize and copy the data in
			copyPacket.resize( originalPacket.size() );
			std::copy( originalPacket.begin(), originalPacket.end(),
				copyPacket.begin() );

			// write the code in
			writeCode( copyPacket.data(), code );

			// set bitflags to type unreliable
			copyPacket.data()[50] = 0x00;

			// set timestamps = 0
			*( ( uint32_t* )( copyPacket.data() + 43 ) ) = 0;
			*( ( uint32_t* )( copyPacket.data() + 61 ) ) = 0;

			// erase redundant data
			copyPacket.erase( copyPacket.begin() + 53, copyPacket.begin() + 60 );

			// nice
			writeSendUnreliableCodelockPacket( copyPacket.data(), lenNew, adHandle );

			// don't spam too much!
			if ( i % 1 == 0 ) std::this_thread::sleep_for( std::chrono::milliseconds( 15 ) );
		}
	}

	printf( "\nDone sending!" );
}


// same as CodelockCracker, but sends UNRELIABLE mode packets
// ideally this won't cause the player to time out
// now includes multithreading + attempting to actually deduce the correct code
void PacketHandler_CodelockCrackerUnreliable(u_char* param, const pcap_pkthdr* header,
	const u_char* pkt_data) {

	uint8_t triggerCode[] = { '7', '7', '7', '7' };

	uint16_t packetIdentifierOffset;

	// handle codelock submission packets. Make sure we're not already sending.
	if (isCodelockPacket(pkt_data, header->len) &&
		compareCodelockPacketCode(pkt_data, triggerCode)
		&& !isSending.load() ) {

		isSending.store( true );
		isCodeFound.store( false );

		// How many times have we failed to guess the code? Count this to get a
		// more accurate code at the end.
		codeFailureCount.store( 0 );

		// Send the code packets on a new thread so we can catch a reply here.
		auto originalPacket = std::vector<u_char>( header->len );
		std::copy( pkt_data, pkt_data + header->len, originalPacket.begin() );
		sendThread = std::thread( SendCodeLockPackets, adHandle, originalPacket );
	}
	else if(packetIdentifierOffset = isCodelockDeniedPacket(pkt_data, header->len)) {
		
		// Not the right code, count this.
		codeFailureCount.store( codeFailureCount.load() + 1 );
	}
	else if(packetIdentifierOffset = isCodelockUnlockedPacket(pkt_data, header->len)) {

		// what we really need at this point is a third thread, to set the timer 
		
		// tell sending thread we found code
		isCodeFound.store(true);

		// print some MORE shit for good measure
		printf("unlock packet, id: %x\n", 
			getCodelockIDFromLockUnlockPacket(pkt_data, packetIdentifierOffset));
	}
}

// 
void PacketHandler_CodelockCracker(u_char* param, const pcap_pkthdr* header,
	const u_char* pkt_data) {

	uint8_t triggerCode[] = { '7', '7', '7', '7' };

	// handle codelock submission packets
	if (isCodelockPacket(pkt_data, header->len) &&
		compareCodelockPacketCode(pkt_data, triggerCode)) {

		printf("Firing ...\n");

		// allocate copy outside of loop
		std::vector<u_char> copyPacket = std::vector<u_char>(header->len);

		// Copy the packet, modify the code number, and send our new copy.
		if (adHandle != nullptr)
		{
			int packetCount = 0;
			for (int i = 0; i < 10000; ++i) {

				if (i == 7777) continue;

				// copy the packet data in fresh
				std::copy(pkt_data, pkt_data + header->len, copyPacket.begin());

				writeSendCodelockPacket(copyPacket.data(), i, 400 + packetCount,
					header->len, adHandle);

				packetCount += 1;
			}

			for (int i = 0; i < 10000; ++i) {

				if (i == 7777) continue;

				// copy the packet data in fresh
				std::copy(pkt_data, pkt_data + header->len, copyPacket.begin());

				writeSendCodelockPacket(copyPacket.data(), i, 400 + packetCount,
					header->len, adHandle);

				packetCount += 1;
			}
		}

		printf("Done firing (can close)\n");
	}
}

// packet handler for the snaptrap field system
// if a snaptrap arm packet is sent, then take it's ID and store it in a set
// for now, used as a trigger: if a code lock packet arrives, use it's up to date
// sequence numbers to send packets to arm all of the stored snaptraps
void PacketHandler_SnaptrapField(u_char* param, const pcap_pkthdr* header,
	const u_char* pkt_data)
{
	// handle snaptrap arm packets
	if (isSnaptrapPacket(pkt_data, header->len))
	{
		unsigned size_prev = snaptrapFieldState.snaptrapIDs.size();

		// for now, every time a snaptrap is manually armed, add it to the
		// list of traps to auto arm
		snaptrapFieldState.snaptrapIDs.insert(readSnaptrapID(pkt_data));

		// copy this packet
		for (unsigned i = 0; i < SNAPTRAP_PACKET_SIZE; i++) {
			snaptrapFieldState.snaptrapPacketLast[i] = pkt_data[i];
		}

		if (snaptrapFieldState.snaptrapIDs.size() > size_prev) printf("Added new snaptrap\n");

		// handle codelock submission packets - used for triggering more snaptrap arm packets
	} else if (isCodelockPacket(pkt_data, header->len)) {

		printf("Triggering snaptraps!\n");

		std::set<uint32_t>::iterator snaptrapIDsIt = snaptrapFieldState.snaptrapIDs.begin();

		// for every one of our stored snaptraps, copy a packet, make
		// the appropriate modifications to the checksums and seq numbers,
		// then send it
		for (unsigned i = 0; i < snaptrapFieldState.snaptrapIDs.size(); i++) {

			// copy last packet data
			std::vector<u_char> copyPacket = std::vector<u_char>(SNAPTRAP_PACKET_SIZE);
			std::copy(snaptrapFieldState.snaptrapPacketLast,
				snaptrapFieldState.snaptrapPacketLast + SNAPTRAP_PACKET_SIZE,
				copyPacket.begin());

			// copy the sequence numbers from the received code lock packet
			// into the snaptrap packet
			copy_sequence_number(pkt_data, copyPacket.data(), 5);
			copy_sequence_number(pkt_data, copyPacket.data(), 11);
			copy_sequence_number(pkt_data, copyPacket.data(), 14);

			// increment the sequence numbers
			increment_sequence_number(copyPacket.data(), 5, 50 + i);
			increment_sequence_number(copyPacket.data(), 11, 50 + i);
			increment_sequence_number(copyPacket.data(), 14, 50 + i);

			// change the snaptrap ID thing
			writeSnaptrapID(copyPacket.data(), *snaptrapIDsIt);

			// increment snaptrap ID iterator
			std::advance(snaptrapIDsIt, 1);

			// sweet sweet checksums
			InsertCrc32(copyPacket.data(), SNAPTRAP_PACKET_SIZE);
			write_checksum_ip(copyPacket.data());
			InsertUDPChecksum(copyPacket.data(), SNAPTRAP_PACKET_SIZE);

			// send the packet
			pcap_sendpacket(adHandle, copyPacket.data(), SNAPTRAP_PACKET_SIZE);
		}
	}
}


// ONLY CONTAINS PCAP SETUP
int main()
{
	pcap_if_t*	allDevs;
	char		errorBuffer[PCAP_ERRBUF_SIZE];

	// Find all available devices.
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, nullptr, &allDevs,
		errorBuffer))
	{
		std::cout << "Error in pcap_finalldevs_ex: " << errorBuffer
			<< std::endl;
		return -1;
	}

	int i = 0;
	for (auto* d = allDevs; d != nullptr; d = d->next, ++i)
	{
		std::cout << i << ". " << d->name;
		if (d->description != nullptr)
		{
			std::cout << d->description << std::endl;
		} else
		{
			std::cout << "No description available." << std::endl;
		}
	}

	if (i == 0)
	{
		std::cout << "No interfaces found! Make sure WinPcap is installed."
			<< std::endl;
		return -1;
	}

	// Choose a device.
	int chosen = 0;
	std::cout << "Enter the interface number( 1 - " << i << " ): ";
	std::cin >> chosen;

	if (chosen < 1 || chosen > i)
	{
		std::cout << "Interface number out of range." << std::endl;
		pcap_freealldevs(allDevs);
		return -1;
	}

	// Move through the device list until we get to the chosen one.
	i = 0;
	auto* d = allDevs;
	for (d = allDevs; i < chosen - 1; d = d->next, ++i)
	{
	}

	// Open the device.
	adHandle = pcap_open(d->name, 65536,
		PCAP_OPENFLAG_PROMISCUOUS, 1000, nullptr, errorBuffer);
	if (adHandle == nullptr)
	{
		std::cout << "Unable to open the adapter. " << d->name
			<< "is not supported by WinPcap" << std::endl;
		pcap_freealldevs(allDevs);
		return -1;
	}

	std::cout << "Listening on " << d->name << std::endl;
	pcap_freealldevs(allDevs);


	bpf_u_int32 mask = 0;
	if (d->addresses != nullptr)
	{
		mask =
			((sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	} else
	{
		mask = 0xFFFFFFFF;
	}

	// Compile and set the packet filter.
	bpf_program code;
	if (pcap_compile(adHandle, &code, FilterString, 1, mask) < 0)
	{
		std::cout << "Unable to compile the packet filter. Check the syntax"
			<< std::endl;
		return -1;
	}

	if (pcap_setfilter(adHandle, &code) < 0)
	{
		std::cout << "Error setting the filter." << std::endl;
		return -1;
	}

	// change handler as desired
	pcap_loop(adHandle, 0, PacketHandler_CodelockCrackerUnreliable, nullptr);

	return 0;
}

