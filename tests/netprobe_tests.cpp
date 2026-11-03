#include <gtest/gtest.h>
#include "netprobe/model/mac_address.hpp"
#include "netprobe/model/ip_address.hpp"
#include "netprobe/parser/ethernet_parser.hpp"
#include "netprobe/parser/ipv4_parser.hpp"
#include "netprobe/parser/transport_parser.hpp"
#include "netprobe/parser/packet_validator.hpp"
#include "netprobe/parser/packet_decoder.hpp"
#include "netprobe/filter/packet_filter.hpp"
#include "netprobe/analyzer/traffic_analyzer.hpp"
#include "netprobe/capture/mock_packet_source.hpp"
#include "netprobe/capture/capture_engine.hpp"
#include "netprobe/diagnostics/ping_service.hpp"

using namespace netprobe;

TEST(ModelTest, MacAddressParsingAndFormatting) {
    auto mac_opt = model::MacAddress::from_string("00:1A:2B:3C:4D:5E");
    ASSERT_TRUE(mac_opt.has_value());
    EXPECT_EQ(mac_opt->to_string(), "00:1a:2b:3c:4d:5e");
    EXPECT_FALSE(mac_opt->is_broadcast());
    EXPECT_FALSE(mac_opt->is_multicast());

    auto bcast = model::MacAddress::broadcast();
    EXPECT_TRUE(bcast.is_broadcast());
    EXPECT_EQ(bcast.to_string(), "ff:ff:ff:ff:ff:ff");

    auto invalid = model::MacAddress::from_string("invalid_mac");
    EXPECT_FALSE(invalid.has_value());
}

TEST(ModelTest, IPv4AddressParsingAndSubnets) {
    auto ip_opt = model::IPv4Address::from_string("192.168.1.100");
    ASSERT_TRUE(ip_opt.has_value());
    EXPECT_EQ(ip_opt->to_string(), "192.168.1.100");
    EXPECT_TRUE(ip_opt->is_private());
    EXPECT_FALSE(ip_opt->is_loopback());

    auto network = model::IPv4Address::from_string("192.168.1.0").value();
    EXPECT_TRUE(ip_opt->matches_cidr(network, 24));
    EXPECT_FALSE(ip_opt->matches_cidr(model::IPv4Address::from_string("10.0.0.0").value(), 8));

    auto loopback = model::IPv4Address::loopback();
    EXPECT_TRUE(loopback.is_loopback());
    EXPECT_EQ(loopback.to_string(), "127.0.0.1");
}

TEST(ParserTest, EthernetParserBasic) {
    std::vector<uint8_t> frame_bytes = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
        0x08, 0x00,
        0x45, 0x00, 0x00, 0x20
    };

    auto frame = parser::EthernetParser::parse(frame_bytes);
    ASSERT_TRUE(frame.has_value());
    EXPECT_EQ(frame->destination().to_string(), "00:11:22:33:44:55");
    EXPECT_EQ(frame->source().to_string(), "66:77:88:99:aa:bb");
    EXPECT_EQ(frame->ether_type(), model::EtherType::IPv4);
    EXPECT_EQ(frame->payload().size(), 4);
    EXPECT_FALSE(frame->vlan_id().has_value());
}

TEST(ParserTest, EthernetParserVlan) {
    std::vector<uint8_t> frame_bytes = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
        0x81, 0x00, 0x00, 0x64,
        0x08, 0x00,
        0xDE, 0xAD, 0xBE, 0xEF
    };

    auto frame = parser::EthernetParser::parse(frame_bytes);
    ASSERT_TRUE(frame.has_value());
    EXPECT_TRUE(frame->vlan_id().has_value());
    EXPECT_EQ(*frame->vlan_id(), 100);
    EXPECT_EQ(frame->ether_type(), model::EtherType::IPv4);
    EXPECT_EQ(frame->payload().size(), 4);
}

TEST(ParserTest, IPv4ParserAndChecksum) {
    std::vector<uint8_t> ip_packet = {
        0x45, 0x00, 0x00, 0x1C,
        0x12, 0x34, 0x40, 0x00,
        0x40, 0x06, 0x00, 0x00,
        192, 168, 1, 10,
        192, 168, 1, 1,
        0x00, 0x50, 0x01, 0xBB, 0x00, 0x00, 0x00, 0x01
    };

    uint16_t csum = parser::PacketValidator::calculate_checksum(core::ByteSpan(ip_packet.data(), 20));
    ip_packet[10] = static_cast<uint8_t>((csum >> 8) & 0xFF);
    ip_packet[11] = static_cast<uint8_t>(csum & 0xFF);

    EXPECT_TRUE(parser::PacketValidator::verify_ipv4_checksum(core::ByteSpan(ip_packet.data(), 20)));

    auto parsed_ip = parser::IPv4Parser::parse(ip_packet);
    ASSERT_TRUE(parsed_ip.has_value());
    EXPECT_EQ(parsed_ip->version(), 4);
    EXPECT_EQ(parsed_ip->ihl(), 5);
    EXPECT_EQ(parsed_ip->total_length(), 28);
    EXPECT_EQ(parsed_ip->source().to_string(), "192.168.1.10");
    EXPECT_EQ(parsed_ip->destination().to_string(), "192.168.1.1");
    EXPECT_EQ(parsed_ip->protocol(), model::IPProtocol::TCP);
    EXPECT_TRUE(parsed_ip->flags().dont_fragment);
    EXPECT_FALSE(parsed_ip->flags().more_fragments);
}

TEST(ParserTest, TransportParserTcpUdpIcmp) {
    std::vector<uint8_t> tcp_segment = {
        0x04, 0xD2, 0x00, 0x50,
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
        0x50, 0x02, 0x72, 0x10,
        0x00, 0x00, 0x00, 0x00
    };

    auto tcp = parser::TransportParser::parse_tcp(tcp_segment);
    ASSERT_TRUE(tcp.has_value());
    EXPECT_EQ(tcp->source_port(), 1234);
    EXPECT_EQ(tcp->destination_port(), 80);
    EXPECT_TRUE(tcp->flags().syn);
    EXPECT_FALSE(tcp->flags().ack);

    std::vector<uint8_t> udp_datagram = {
        0x13, 0x88, 0x00, 0x35,
        0x00, 0x0C, 0x00, 0x00,
        0xDE, 0xAD, 0xBE, 0xEF
    };

    auto udp = parser::TransportParser::parse_udp(udp_datagram);
    ASSERT_TRUE(udp.has_value());
    EXPECT_EQ(udp->source_port(), 5000);
    EXPECT_EQ(udp->destination_port(), 53);
    EXPECT_EQ(udp->length(), 12);
    EXPECT_EQ(udp->payload().size(), 4);

    std::vector<uint8_t> icmp_raw = {
        0x08, 0x00, 0x00, 0x00,
        0x12, 0x34, 0x00, 0x01,
        0x61, 0x62, 0x63, 0x64
    };

    auto icmp = parser::TransportParser::parse_icmp(icmp_raw);
    ASSERT_TRUE(icmp.has_value());
    EXPECT_EQ(icmp->type(), model::IcmpType::EchoRequest);
    EXPECT_EQ(icmp->identifier(), 0x1234);
    EXPECT_EQ(icmp->sequence_number(), 1);
}

TEST(FilterTest, PacketFilterExpressionAndMatching) {
    auto filter_opt = filter::PacketFilter::parse_expression("tcp port 80");
    ASSERT_TRUE(filter_opt.has_value());

    std::vector<uint8_t> full_frame = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
        0x08, 0x00,
        0x45, 0x00, 0x00, 0x28,
        0x00, 0x01, 0x00, 0x00,
        0x40, 0x06, 0x00, 0x00,
        10, 0, 0, 1,
        10, 0, 0, 2,
        0x04, 0xD2, 0x00, 0x50,
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
        0x50, 0x02, 0x72, 0x10,
        0x00, 0x00, 0x00, 0x00
    };

    auto parsed = parser::PacketDecoder::decode(full_frame, std::chrono::system_clock::now(), "test0");
    ASSERT_TRUE(parsed.has_value());
    EXPECT_TRUE(filter_opt->matches(*parsed));

    auto filter_udp = filter::PacketFilter::parse_expression("udp");
    ASSERT_TRUE(filter_udp.has_value());
    EXPECT_FALSE(filter_udp->matches(*parsed));
}

TEST(AnalyzerTest, TrafficStatsAggregation) {
    analyzer::TrafficAnalyzer analyzer;

    std::vector<uint8_t> full_frame = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
        0x08, 0x00,
        0x45, 0x00, 0x00, 0x28,
        0x00, 0x01, 0x00, 0x00,
        0x40, 0x06, 0x00, 0x00,
        192, 168, 1, 5,
        192, 168, 1, 10,
        0x00, 0x50, 0x04, 0xD2,
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
        0x50, 0x10, 0x72, 0x10,
        0x00, 0x00, 0x00, 0x00
    };

    auto parsed = parser::PacketDecoder::decode(full_frame, std::chrono::system_clock::now(), "test0");
    ASSERT_TRUE(parsed.has_value());

    analyzer.process_packet(*parsed);
    analyzer.process_packet(*parsed);

    auto snap = analyzer.snapshot();
    EXPECT_EQ(snap.total_packets, 2);
    EXPECT_EQ(snap.total_bytes, full_frame.size() * 2);
    EXPECT_EQ(snap.ipv4_packets, 2);
    EXPECT_EQ(snap.tcp_packets, 2);

    auto flows = analyzer.active_flows();
    ASSERT_EQ(flows.size(), 1);
    EXPECT_EQ(flows[0].second.packets, 2);
}

TEST(CaptureTest, MockPacketSourceAndEngine) {
    auto source = std::make_shared<capture::MockPacketSource>("mock_test");
    capture::CaptureEngine engine(source);

    std::vector<uint8_t> dummy_frame(60, 0);
    dummy_frame[12] = 0x08;
    dummy_frame[13] = 0x06;

    std::atomic<int> received_count{0};
    engine.add_listener([&](const model::ParsedPacket&, const core::RawPacket&) {
        received_count++;
    });

    engine.start();

    source->inject_packet(dummy_frame);
    source->inject_packet(dummy_frame);

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    engine.stop();
    EXPECT_EQ(received_count.load(), 2);
    EXPECT_EQ(engine.captured_packets_count(), 2);
}

TEST(DiagnosticsTest, MockPingExecution) {
    diagnostics::MockPingService ping_service;
    diagnostics::PingRequest request{
        .target_ip = model::IPv4Address(8, 8, 8, 8),
        .count = 3,
        .payload_size = 32,
        .interval = std::chrono::milliseconds(10),
        .timeout = std::chrono::milliseconds(500)
    };

    auto summary = ping_service.execute(request);
    EXPECT_EQ(summary.packets_transmitted, 3);
    EXPECT_EQ(summary.packets_received, 3);
    EXPECT_DOUBLE_EQ(summary.packet_loss_percent, 0.0);
    EXPECT_GT(summary.avg_rtt_ms, 0.0);
}
