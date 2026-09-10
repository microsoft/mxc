// Hands the kernel a finished Ethernet frame addressed to a destination the
// container's egress policy does not allow.
//
// An ordinary ping asks the IP stack to build and route the packet, and every
// netfilter hook the egress policy installs lives on that path.  AF_PACKET
// starts below it: the frame goes to the device, and LOCAL_OUT is never
// consulted.  Sending the same protocol to the same address both ways is what
// makes the path the only variable between the two.
//
// The protocol is an argument rather than a branch so that path and protocol
// stay independent axes.  The old test varied both at once and could not
// attribute the difference to either.
//
// usage: raw_egress_probe <interface> <dst-mac> <dst-ip> <icmp|tcp|udp>
// exit:  0 frame accepted by the kernel, 1 refused, 2 bad usage or setup

#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#define ICMP_PAYLOAD 32
#define SOURCE_PORT 40001
#define DESTINATION_PORT 443

// One's-complement sum over the buffer, folded to 16 bits and inverted.
static unsigned short checksum(const void *data, int length)
{
    const unsigned char *bytes = data;
    unsigned long sum = 0;

    while (length > 1)
    {
        sum += (unsigned long)((bytes[0] << 8) | bytes[1]);
        bytes += 2;
        length -= 2;
    }

    if (length == 1)
    {
        sum += (unsigned long)(bytes[0] << 8);
    }

    while (sum >> 16)
    {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    return (unsigned short)(~sum & 0xffff);
}

// TCP and UDP checksums cover a pseudo-header of addresses and length that is
// not transmitted, so the sum is taken over that block and the segment
// together rather than over the segment alone.
static unsigned short transport_checksum(struct in_addr source,
                                         struct in_addr destination,
                                         unsigned char protocol,
                                         const unsigned char *segment,
                                         int length)
{
    unsigned char block[12 + 1500];

    memcpy(block, &source.s_addr, 4);
    memcpy(block + 4, &destination.s_addr, 4);
    block[8] = 0;
    block[9] = protocol;
    block[10] = (unsigned char)(length >> 8);
    block[11] = (unsigned char)(length & 0xff);
    memcpy(block + 12, segment, (size_t)length);

    return checksum(block, 12 + length);
}

static int parse_mac(const char *text, unsigned char *out)
{
    unsigned int octet[6];

    if (sscanf(text, "%x:%x:%x:%x:%x:%x",
               &octet[0], &octet[1], &octet[2],
               &octet[3], &octet[4], &octet[5]) != 6)
    {
        return -1;
    }

    for (int i = 0; i < 6; i++)
    {
        out[i] = (unsigned char)octet[i];
    }

    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 5)
    {
        fprintf(stderr, "usage: %s <interface> <dst-mac> <dst-ip> <icmp|tcp|udp>\n",
                argv[0]);
        return 2;
    }

    const char *interface = argv[1];
    const char *protocol_name = argv[4];
    unsigned char ip_protocol;

    if (strcmp(protocol_name, "icmp") == 0)
    {
        ip_protocol = 1;
    }
    else if (strcmp(protocol_name, "tcp") == 0)
    {
        ip_protocol = 6;
    }
    else if (strcmp(protocol_name, "udp") == 0)
    {
        ip_protocol = 17;
    }
    else
    {
        fprintf(stderr, "PROBE_SETUP_FAILED: %s is not icmp, tcp, or udp\n",
                protocol_name);
        return 2;
    }

    unsigned char destination_mac[6];
    struct in_addr destination_ip;

    if (parse_mac(argv[2], destination_mac) != 0)
    {
        fprintf(stderr, "PROBE_SETUP_FAILED: %s is not a MAC address\n", argv[2]);
        return 2;
    }

    if (inet_aton(argv[3], &destination_ip) == 0)
    {
        fprintf(stderr, "PROBE_SETUP_FAILED: %s is not an IPv4 address\n", argv[3]);
        return 2;
    }

    // Creating this socket is what CAP_NET_RAW gates.  A confinement that
    // removed the capability, or a seccomp filter on AF_PACKET, stops the
    // program here rather than at the send.
    int packet_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if (packet_socket < 0)
    {
        printf("MXC_RAW_SOCKET_REFUSED errno=%d (%s)\n", errno, strerror(errno));
        return 1;
    }

    struct ifreq request;
    memset(&request, 0, sizeof(request));
    strncpy(request.ifr_name, interface, IFNAMSIZ - 1);

    if (ioctl(packet_socket, SIOCGIFINDEX, &request) < 0)
    {
        fprintf(stderr, "PROBE_SETUP_FAILED: no interface %s (%s)\n",
                interface, strerror(errno));
        return 2;
    }
    int interface_index = request.ifr_ifindex;

    if (ioctl(packet_socket, SIOCGIFHWADDR, &request) < 0)
    {
        fprintf(stderr, "PROBE_SETUP_FAILED: %s has no hardware address (%s)\n",
                interface, strerror(errno));
        return 2;
    }
    unsigned char source_mac[6];
    memcpy(source_mac, request.ifr_hwaddr.sa_data, 6);

    memset(&request, 0, sizeof(request));
    strncpy(request.ifr_name, interface, IFNAMSIZ - 1);
    if (ioctl(packet_socket, SIOCGIFADDR, &request) < 0)
    {
        fprintf(stderr, "PROBE_SETUP_FAILED: %s has no IPv4 address (%s)\n",
                interface, strerror(errno));
        return 2;
    }
    struct in_addr source_ip =
        ((struct sockaddr_in *)&request.ifr_addr)->sin_addr;

    // Built before the frame so the IP header's total-length field has a real
    // number to carry.
    unsigned char transport[20 + ICMP_PAYLOAD];
    int transport_length;

    memset(transport, 0, sizeof(transport));

    if (ip_protocol == 1)
    {
        transport[0] = 8;
        transport[4] = 0x4d;
        transport[5] = 0x58;
        transport[7] = 0x01;
        memset(transport + 8, 0x61, ICMP_PAYLOAD);
        transport_length = 8 + ICMP_PAYLOAD;

        unsigned short sum = checksum(transport, transport_length);
        transport[2] = (unsigned char)(sum >> 8);
        transport[3] = (unsigned char)(sum & 0xff);
    }
    else if (ip_protocol == 6)
    {
        transport[0] = (unsigned char)(SOURCE_PORT >> 8);
        transport[1] = (unsigned char)(SOURCE_PORT & 0xff);
        transport[2] = (unsigned char)(DESTINATION_PORT >> 8);
        transport[3] = (unsigned char)(DESTINATION_PORT & 0xff);
        transport[8] = 0x4d;
        // Five 32-bit words of header and no options, then the SYN bit.
        transport[12] = 0x50;
        transport[13] = 0x02;
        transport[14] = 0xff;
        transport[15] = 0xff;
        transport_length = 20;

        unsigned short sum = transport_checksum(source_ip, destination_ip,
                                                ip_protocol, transport,
                                                transport_length);
        transport[16] = (unsigned char)(sum >> 8);
        transport[17] = (unsigned char)(sum & 0xff);
    }
    else
    {
        unsigned short udp_length = 8 + ICMP_PAYLOAD;

        transport[0] = (unsigned char)(SOURCE_PORT >> 8);
        transport[1] = (unsigned char)(SOURCE_PORT & 0xff);
        transport[2] = (unsigned char)(DESTINATION_PORT >> 8);
        transport[3] = (unsigned char)(DESTINATION_PORT & 0xff);
        transport[4] = (unsigned char)(udp_length >> 8);
        transport[5] = (unsigned char)(udp_length & 0xff);
        memset(transport + 8, 0x61, ICMP_PAYLOAD);
        transport_length = udp_length;

        unsigned short sum = transport_checksum(source_ip, destination_ip,
                                                ip_protocol, transport,
                                                transport_length);
        transport[6] = (unsigned char)(sum >> 8);
        transport[7] = (unsigned char)(sum & 0xff);
    }

    unsigned char frame[14 + 20 + 20 + ICMP_PAYLOAD];
    int frame_length = 14 + 20 + transport_length;

    memset(frame, 0, sizeof(frame));

    memcpy(frame, destination_mac, 6);
    memcpy(frame + 6, source_mac, 6);
    frame[12] = 0x08;
    frame[13] = 0x00;

    unsigned char *ip = frame + 14;
    ip[0] = 0x45;
    ip[1] = 0x00;
    unsigned short total_length = (unsigned short)(20 + transport_length);
    ip[2] = (unsigned char)(total_length >> 8);
    ip[3] = (unsigned char)(total_length & 0xff);
    ip[4] = 0x4d;
    ip[5] = 0x58;
    ip[6] = 0x40;
    ip[8] = 64;
    ip[9] = ip_protocol;
    memcpy(ip + 12, &source_ip.s_addr, 4);
    memcpy(ip + 16, &destination_ip.s_addr, 4);
    unsigned short ip_checksum = checksum(ip, 20);
    ip[10] = (unsigned char)(ip_checksum >> 8);
    ip[11] = (unsigned char)(ip_checksum & 0xff);

    memcpy(ip + 20, transport, (size_t)transport_length);

    struct sockaddr_ll target;
    memset(&target, 0, sizeof(target));
    target.sll_family = AF_PACKET;
    target.sll_protocol = htons(ETH_P_IP);
    target.sll_ifindex = interface_index;
    target.sll_halen = 6;
    memcpy(target.sll_addr, destination_mac, 6);

    ssize_t sent = sendto(packet_socket, frame, (size_t)frame_length, 0,
                          (struct sockaddr *)&target, sizeof(target));
    if (sent < 0)
    {
        printf("MXC_RAW_SEND_REFUSED errno=%d (%s)\n", errno, strerror(errno));
        close(packet_socket);
        return 1;
    }

    printf("MXC_RAW_SENT %zd bytes of %s to %s via %s\n",
           sent, protocol_name, argv[3], interface);
    close(packet_socket);
    return 0;
}
