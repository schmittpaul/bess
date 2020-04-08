#include "netmicroscope.h"
#include "../utils/cuckoo_map.h"
#include "nm_stats.h"

#include "../utils/ether.h"
#include "../utils/ip.h"
#include "../utils/tcp.h"
#include "../utils/udp.h"
using bess::utils::be32_t;
using bess::utils::NM_Flowcache;
using bess::utils::ToIpv4Address;


NM_Flowcache::FlowTuple GetTuple(bess::Packet *pkt) {
  using bess::utils::Ethernet;
  using bess::utils::Ipv4;
  using bess::utils::Tcp;
  using bess::utils::Udp;

  Ethernet *eth = pkt->head_data<Ethernet *>();
  Ipv4 *ip = reinterpret_cast<Ipv4 *>(eth + 1);
  size_t ip_bytes = ip->header_length << 2;

  NM_Flowcache::FlowTuple ft;

  if (ip->protocol & Ipv4::kUdp) {
    Udp *udp = reinterpret_cast<Udp *>(reinterpret_cast<uint8_t *>(ip) +
                                       ip_bytes);  // Assumes a l-4 header
    ft.client_ip = ip->src.value();
    ft.server_ip = ip->dst.value();
    ft.client_port = udp->src_port.value();
    ft.server_port = udp->dst_port.value();
    ft.protocol = ip->protocol;
  } else if (ip->protocol & Ipv4::kTcp) {
    Tcp *tcp = reinterpret_cast<Tcp *>(reinterpret_cast<uint8_t *>(ip) +
                                       ip_bytes);  // Assumes a l-4 header

    ft.protocol = ip->protocol;
    // This is a server responding to a client
    if ((tcp->flags & Tcp::Flag::kSyn) && (tcp->flags & Tcp::Flag::kAck)) {
      ft.client_ip = ip->dst.value();
      ft.server_ip = ip->src.value();
      ft.client_port = tcp->dst_port.value();
      ft.server_port = tcp->src_port.value();
    } else {
      ft.client_ip = ip->src.value();
      ft.server_ip = ip->dst.value();
      ft.client_port = tcp->src_port.value();
      ft.server_port = tcp->dst_port.value();
    }
  }
  return ft;
}

// void netmicroscope::ProcessPacket(bess::Packet *pkt) {
//   using bess::utils::Ethernet;
//   using bess::utils::Ipv4;
//   using bess::utils::Tcp;
//   using bess::utils::Udp;
//   Ethernet *eth = pkt->head_data<Ethernet *>();
//   Ipv4 *ip = reinterpret_cast<Ipv4 *>(eth + 1);
//   size_t ip_bytes = ip->header_length << 2;

//   if (ip->protocol & Ipv4::kUdp) {
//     Udp *udp = reinterpret_cast<Udp *>(reinterpret_cast<uint8_t *>(ip) +
//                                        ip_bytes);  // Assumes a l-4 header
//     ft.client_ip = ip->src.value();
//     ft.server_ip = ip->dst.value();
//     ft.client_port = udp->src_port.value();
//     ft.server_port = udp->dst_port.value();
//     ft.protocol = ip->protocol;
//   } else if (ip->protocol & Ipv4::kTcp) {
//     Tcp *tcp = reinterpret_cast<Tcp *>(reinterpret_cast<uint8_t *>(ip) +
//                                        ip_bytes);  // Assumes a l-4 header

//     ft.protocol = ip->protocol;
//     // This is a server responding to a client
//     if ((tcp->flags & Tcp::Flag::kSyn) && (tcp->flags & Tcp::Flag::kAck)) {
//       ft.client_ip = ip->dst.value();
//       ft.server_ip = ip->src.value();
//       ft.client_port = tcp->dst_port.value();
//       ft.server_port = tcp->src_port.value();
//     } else {
//       ft.client_ip = ip->src.value();
//       ft.server_ip = ip->dst.value();
//       ft.client_port = tcp->src_port.value();
//       ft.server_port = tcp->dst_port.value();
//     }
//   }
//   return;
// }

void netmicroscope::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  int cnt = batch->cnt();
  for (int i = 0; i < cnt; i++) {
    bess::Packet *pkt = batch->pkts()[i];

    using bess::utils::Ethernet;
    using bess::utils::Ipv4;
    using bess::utils::Udp;

    NM_Flowcache::FlowTuple ft = GetTuple(pkt);

    auto it = NMFC.flowcache.Find(ft);

    if (it == nullptr) {
      NM_Flowcache::Flow *f = new NM_Flowcache::Flow(ft);
      f->fc.clientPackets += 1;
      NMFC.flowcache.Insert(ft, f);
    } else {
      it->second->fc.clientPackets += 1;
    }
  }

  RunNextModule(ctx, batch);
}

ADD_MODULE(netmicroscope, "netmicroscope",
           "Implements netmicroscope code to extract stream information")