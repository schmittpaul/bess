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

#ifndef BESS_UTILS_NM_CACHE_H_
#define BESS_UTILS_NM_CACHE_H_

#include "cuckoo_map.h"

using bess::utils::CuckooMap;

namespace bess {
namespace utils {

class NM_Flowcache {
 public:
  // 5 tuple id to identify a flow from a packet header information.
  struct FlowTuple {
    uint32_t client_ip;
    uint32_t server_ip;
    uint16_t client_port;
    uint16_t server_port;
    uint8_t protocol;
  };

  // Statistics to keep for a flow
  class Flow {
   public:
    int pkts;  // packet counter
    int pktsup;
    int pktsdown;
    FlowTuple ft;

    Flow(FlowTuple new_tuple)
        : pkts(0), pktsup(0), pktsdown(0), ft(new_tuple){};
  };

  // Obviously not an ideal hash, but we require it to be reversible such that
  // both directions of the flow map to the same key
  struct fastHash {
    uint64_t operator()(const FlowTuple &ft) const {
      std::size_t client = std::hash<uint32_t>()(ft.client_ip);
      std::size_t server = std::hash<uint32_t>()(ft.server_ip);
      std::size_t cport = std::hash<uint16_t>()(ft.client_port);
      std::size_t sport = std::hash<uint16_t>()(ft.server_port);
      std::size_t proto = std::hash<uint8_t>()(ft.protocol);

      return client ^ server ^ cport ^ sport ^ proto;
    }
  };

  // to compare two FlowTuple for equality in a hash table
  struct EqualTo {
    bool operator()(const FlowTuple &id1, const FlowTuple &id2) const {
      bool ips = (id1.client_ip == id2.client_ip) && (id1.server_ip == id2.server_ip);
      bool ports =
          (id1.client_port == id2.client_port) && (id1.server_port == id2.server_port);
      bool ipsreversed =
          (id1.client_ip == id2.server_ip) && (id1.server_ip == id2.client_ip);
      bool portsreversed =
          (id1.client_port == id2.server_port) && (id1.server_port == id2.client_port);
      return ((ips && ports) || (ipsreversed && portsreversed)) &&
             (id1.protocol == id2.protocol);
    }
  };

  // The actual flowcache that workers will interact with
  CuckooMap<FlowTuple, Flow *, fastHash, EqualTo> flowcache;

  NM_Flowcache(){};

 private:
  //  Takes a Packet to get a flow id for. Returns the 5 element identifier
  //  for the flow that the packet belongs to
  FlowTuple GetTuple(bess::Packet *pkt);
};

}  // namespace utils
}  // namespace bess

#endif  // BESS_UTILS_NM_CACHE_H_
