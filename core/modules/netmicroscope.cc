/* BESS version based on cryptopANT 1.2.1 (2019-09-30)
 * Modified by Paul Schmitt
 * Copyright (C) 2004-2019 by the University of Southern California
 * $Id: 89d8a3f3fea9f54bc16a49c7c9d8788716f83f8f $
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA.
 *
 */

#include "netmicroscope.h"

#include "../utils/ether.h"
#include "../utils/ip.h"
#include "../utils/udp.h"
using bess::utils::be32_t;
using bess::utils::ToIpv4Address;

netmicroscope::FlowTuple netmicroscope::GetTuple(bess::Packet *pkt) {
  using bess::utils::Ethernet;
  using bess::utils::Ipv4;
  using bess::utils::Udp;

  Ethernet *eth = pkt->head_data<Ethernet *>();
  Ipv4 *ip = reinterpret_cast<Ipv4 *>(eth + 1);
  size_t ip_bytes = ip->header_length << 2;
  Udp *udp = reinterpret_cast<Udp *>(reinterpret_cast<uint8_t *>(ip) +
                                     ip_bytes);  // Assumes a l-4 header
  // TODO: handle packet fragmentation
  FlowTuple ft = {ip->src.value(), ip->dst.value(), udp->src_port.value(),
                  udp->dst_port.value(), ip->protocol};
  return ft;
}

void netmicroscope::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  int cnt = batch->cnt();
  for (int i = 0; i < cnt; i++) {
    bess::Packet *pkt = batch->pkts()[i];

    using bess::utils::Ethernet;
    using bess::utils::Ipv4;
    using bess::utils::Udp;

    FlowTuple ft = GetTuple(pkt);

    auto it = flowcache.find(ft);

    if (it == flowcache.end()) {
      Flow *f = new Flow(ft);
      f->pkts += 1;
      flowcache.insert(std::make_pair(ft, f));
    } else {
      it->second->pkts += 1;
    }
  }
  for (auto ii = flowcache.begin(); ii != flowcache.end(); ii++)
    printf("Cache: %s %s %d %d %d\n",
           ToIpv4Address(be32_t(ii->first.src_ip)).c_str(),
           ToIpv4Address(be32_t(ii->first.dst_ip)).c_str(), ii->first.src_port,
           ii->first.dst_port, ii->second->pkts);
  printf("=================\n");
  RunNextModule(ctx, batch);
}

ADD_MODULE(netmicroscope, "netmicroscope",
           "Implements netmicroscope code to extract stream information")