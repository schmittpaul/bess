// Copyright (c) 2016-2017, Nefeli Networks, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// * Redistributions of source code must retain the above copyright notice, this
// list of conditions and the following disclaimer.
//
// * Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// * Neither the names of the copyright holders nor the names of their
// contributors may be used to endorse or promote products derived from this
// software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

#ifndef BESS_UTILS_NM_UTILS_H_
#define BESS_UTILS_NM_UTILS_H_

#include "aho_corasick.h"
#include "ether.h"
#include "format.h"
#include "ip.h"
#include "nm_cache.h"
#include "tcp.h"
#include "udp.h"

namespace bess {
namespace utils {

using bess::utils::be32_t;
using bess::utils::NM_Flowcache;

// struct ServiceEntry {
//   std::string name;
//   bess::utils::trie aho_corasick_map;

//   // ServiceEntry() {
//   //   name = "";
//   //   aho_corasick_map = bess::utils::trie();
//   // };
// };

// NM_Flowcache::FlowTuple GetTuple(bess::Packet *pkt);
// inline NM_Flowcache::FlowTuple GetTuple(bess::Packet *pkt) {
//   using bess::utils::Ethernet;
//   using bess::utils::Ipv4;
//   using bess::utils::Tcp;
//   using bess::utils::Udp;

//   Ethernet *eth = pkt->head_data<Ethernet *>();
//   Ipv4 *ip = reinterpret_cast<Ipv4 *>(eth + 1);
//   size_t ip_bytes = ip->header_length << 2;

//   NM_Flowcache::FlowTuple ft;

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
//   return ft;
// };

}  // namespace utils
}  // namespace bess

#endif  // BESS_UTILS_NM_UTILS_H_
