#include "netmicroscope.h"
#include "../utils/cuckoo_map.h"
#include "nm_stats.h"

#include "../utils/ether.h"
#include "../utils/ip.h"
#include "../utils/udp.h"
using bess::utils::be32_t;
using bess::utils::NM_Flowcache;
using bess::utils::ToIpv4Address;


NM_Flowcache::FlowTuple GetTuple(bess::Packet *pkt) {
  using bess::utils::Ethernet;
  using bess::utils::Ipv4;
  using bess::utils::Udp;

  Ethernet *eth = pkt->head_data<Ethernet *>();
  Ipv4 *ip = reinterpret_cast<Ipv4 *>(eth + 1);
  size_t ip_bytes = ip->header_length << 2;
  Udp *udp = reinterpret_cast<Udp *>(reinterpret_cast<uint8_t *>(ip) +
                                     ip_bytes);  // Assumes a l-4 header
  // TODO: handle packet fragmentation
  NM_Flowcache::FlowTuple ft = {ip->src.value(), ip->dst.value(),
                                udp->src_port.value(), udp->dst_port.value(),
                                ip->protocol};
  return ft;
}

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
      f->pkts += 1;
      NMFC.flowcache.Insert(ft, f);
    } else {
      it->second->pkts += 1;
    }
  }

  RunNextModule(ctx, batch);
}

ADD_MODULE(netmicroscope, "netmicroscope",
           "Implements netmicroscope code to extract stream information")