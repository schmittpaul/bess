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

#ifndef BESS_MODULES_NETMICROSCOPE_H_
#define BESS_MODULES_NETMICROSCOPE_H_

#include "../module.h"

uint64_t fnv_basis = 14695981039346656037u;
uint64_t fnv_prime = 1099511628211u;

class netmicroscope final : public Module {
 public:
  // 5 tuple id to identify a flow from a packet header information.
  struct FlowTuple {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    bool operator==(const FlowTuple &other) const {
      return (this->src_ip == other.src_ip && this->dst_ip == other.dst_ip &&
              this->src_port == other.src_port &&
              this->dst_port == other.dst_port &&
              this->protocol == other.protocol) ||
             (this->src_ip == other.dst_ip && this->dst_ip == other.src_ip &&
              this->src_port == other.dst_port &&
              this->dst_port == other.src_port &&
              this->protocol == other.protocol);
    }
  };

  class Flow {
   public:
    int pkts;  // packet counter
    int pktsup;
    int pktsdown;
    FlowTuple ft;

    Flow(FlowTuple new_tuple)
        : pkts(0), pktsup(0), pktsdown(0), ft(new_tuple){};
  };

  // hashes a FlowTuple
  struct Hash {
    // a similar method to boost's hash_combine in order to combine hashes
    inline void combine(std::size_t &hash, const unsigned int &val) const {
      std::hash<unsigned int> hasher;
      hash ^= hasher(val) + 0x9e3779b9 + (hash << 6) + (hash >> 2);
    }
    size_t operator()(const FlowTuple &ft) const {
      // bess::utils::HashResult operator()(const FlowTuple &ft) const {
      std::size_t hash = 0;
      combine(hash, ft.src_ip);
      combine(hash, ft.dst_ip);
      combine(hash, ft.src_port);
      combine(hash, ft.dst_port);
      combine(hash, (uint32_t)ft.protocol);
      return hash;
    }
  };
  struct fastHash {
    size_t operator()(const FlowTuple &ft) const {
      std::size_t hash = 0;
      hash ^= ft.src_ip;
      hash ^= ft.dst_ip;
      hash ^= ft.src_port;
      hash ^= ft.dst_port;
      hash ^= ft.protocol;
      return hash;
    }
  };

  struct fastHash2 {
    uint64_t operator()(const FlowTuple &ft) const {
      std::size_t src = std::hash<uint32_t>()(ft.src_ip);
      std::size_t dst = std::hash<uint32_t>()(ft.dst_ip);
      std::size_t sport = std::hash<uint16_t>()(ft.src_port);
      std::size_t dport = std::hash<uint16_t>()(ft.dst_port);
      std::size_t proto = std::hash<uint8_t>()(ft.protocol);

      return src ^ dst ^ sport ^ dport ^ proto;
    }
  };

  std::unordered_map<FlowTuple, Flow *, fastHash2> flowcache;

  netmicroscope() : Module() { max_allowed_workers_ = Worker::kMaxWorkers; }

  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;

 private:
  //  Takes a Packet to get a flow id for. Returns the 5 element identifier
  //  for the flow that the packet belongs to
  FlowTuple GetTuple(bess::Packet *pkt);
};

#endif  // BESS_MODULES_NETMICROSCOPE_H_