#include <iostream>
#include "stdlib.h"
#include "PcapLiveDeviceList.h"
#include "SystemUtils.h"

struct PacketStats
{
  int ethPacketCount;
  int ipv4PacketCount;
  int ipv6PacketCount;
  int tcpPacketCount;
  int udpPacketCount;
  int dnsPacketCount;
  int httpPacketCount;
  int sslPacketCount;

  /**
   * Clear all stats
   */
  void clear()
  {
    ethPacketCount = 0;
    ipv4PacketCount = 0;
    ipv6PacketCount = 0;
    tcpPacketCount = 0;
    udpPacketCount = 0;
    tcpPacketCount = 0;
    dnsPacketCount = 0;
    httpPacketCount = 0;
    sslPacketCount = 0;
  }

  /**
   * C'tor
   */
  PacketStats() { clear(); }

  /**
   * Collect stats from a packet
   */
  void consumePacket(pcpp::Packet &packet)
  {
    if (packet.isPacketOfType(pcpp::Ethernet))
      ethPacketCount++;
    if (packet.isPacketOfType(pcpp::IPv4))
      ipv4PacketCount++;
    if (packet.isPacketOfType(pcpp::IPv6))
      ipv6PacketCount++;
    if (packet.isPacketOfType(pcpp::TCP))
      tcpPacketCount++;
    if (packet.isPacketOfType(pcpp::UDP))
      udpPacketCount++;
    if (packet.isPacketOfType(pcpp::DNS))
      dnsPacketCount++;
    if (packet.isPacketOfType(pcpp::HTTP))
      httpPacketCount++;
    if (packet.isPacketOfType(pcpp::SSL))
      sslPacketCount++;
  }

  /**
   * Print stats to console
   */
  void printToConsole()
  {
    std::cout
        << "Ethernet packet count: " << ethPacketCount << std::endl
        << "IPv4 packet count:     " << ipv4PacketCount << std::endl
        << "IPv6 packet count:     " << ipv6PacketCount << std::endl
        << "TCP packet count:      " << tcpPacketCount << std::endl
        << "UDP packet count:      " << udpPacketCount << std::endl
        << "DNS packet count:      " << dnsPacketCount << std::endl
        << "HTTP packet count:     " << httpPacketCount << std::endl
        << "SSL packet count:      " << sslPacketCount << std::endl;
  }
};

/**
 * A callback function for the async capture which is called each time a packet is captured
 */
static void onPacketArrives(pcpp::RawPacket *packet, pcpp::PcapLiveDevice *dev, void *cookie);

/**
 * main method of the application
 */
int main(int argc, char *argv[])
{
  // IPv4 address of the interface we want to sniff
  std::string interfaceIPAddr = "172.18.0.2";

  // find the interface by IP address
  pcpp::PcapLiveDevice *dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(interfaceIPAddr);
  if (dev == NULL)
  {
    std::cerr << "Cannot find interface with IPv4 address of '" << interfaceIPAddr << "'" << std::endl;
    return 1;
  }

  // before capturing packets let's print some info about this interface
  std::cout
      << "Interface info:" << std::endl
      << "   Interface name:        " << dev->getName() << std::endl           // get interface name
      << "   Interface description: " << dev->getDesc() << std::endl           // get interface description
      << "   MAC address:           " << dev->getMacAddress() << std::endl     // get interface MAC address
      << "   Default gateway:       " << dev->getDefaultGateway() << std::endl // get default gateway
      << "   Interface MTU:         " << dev->getMtu() << std::endl;           // get interface MTU

  if (dev->getDnsServers().size() > 0)
    std::cout << "   DNS server:            " << dev->getDnsServers().at(0) << std::endl;

  // open the device before start capturing/sending packets
  if (!dev->open())
  {
    std::cerr << "Cannot open device" << std::endl;
    return 1;
  }

  PacketStats stats;

  std::cout << std::endl
            << "Starting async capture..." << std::endl;

  // start capture in async mode. Give a callback function to call to whenever a packet is captured and the stats object as the cookie
  dev->startCapture(onPacketArrives, &stats);

  // sleep for 10 seconds in main thread, in the meantime packets are captured in the async thread
  pcpp::multiPlatformSleep(10);

  // stop capturing packets
  dev->stopCapture();

  // print results
  std::cout << "Results:" << std::endl;
  stats.printToConsole();
}

static void onPacketArrives(pcpp::RawPacket *packet, pcpp::PcapLiveDevice *dev, void *cookie)
{
  // extract the stats object form the cookie
  PacketStats *stats = (PacketStats *)cookie;

  // parsed the raw packet
  pcpp::Packet parsedPacket(packet);

  // collect stats from packet
  stats->consumePacket(parsedPacket);
}