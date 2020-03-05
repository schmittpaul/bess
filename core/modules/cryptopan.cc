// Copyright (c) 2014-2016, The Regents of the University of California.
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

#include "cryptopan.h"

#include "../utils/ether.h"
#include "../utils/ip.h"
#include "../utils/panonymizer.h"
#include "../utils/udp.h"

using bess::utils::be32_t;
using bess::utils::Ethernet;
using bess::utils::Ipv4;
using bess::utils::PAnonymizer;
using bess::utils::Udp;

void CryptoPAn::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  int cnt = batch->cnt();
  unsigned char cryptopan_key[32] = {
      211, 74,  24, 11, 91, 14,  27,  18,  190, 101, 191, 22, 73, 144, 125, 16,
      219, 159, 13, 13, 11, 121, 101, 139, 198, 8,   176, 45, 42, 132, 34,  2};
  // Create an instance of PAnonymizer with the key
  PAnonymizer anonymizer(cryptopan_key);

  for (int i = 0; i < cnt; i++) {
    bess::Packet *pkt = batch->pkts()[i];

    Ethernet *eth = pkt->head_data<Ethernet *>();
    Ipv4 *ip = reinterpret_cast<Ipv4 *>(eth + 1);

    // anonymize needs uint32
    uint32_t src, dst;
    src = ip->src.value();
    dst = ip->dst.value();

    // replace source and destination with CryptoPAn IPs
    ip->src = (be32_t)anonymizer.anonymize(src);
    ip->dst = (be32_t)anonymizer.anonymize(dst);
  }

  RunNextModule(ctx, batch);
}

ADD_MODULE(CryptoPAn, "cryptopan",
           "anonymizes IP addresses using the CryptoPAn algorithm")
