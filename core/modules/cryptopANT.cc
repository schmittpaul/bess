/*
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

#include "cryptopANT.h"

#include "../utils/ether.h"
#include "../utils/ip.h"
#include "../utils/udp.h"
#include "../utils/cryptopANTlib.h"

using bess::utils::be32_t;
using bess::utils::Ethernet;
using bess::utils::Ipv4;

static int pass_bits4 = 0;

bess::utils::scramble_crypt_t key_crypto =
    bess::utils::scramble_crypt_t::SCRAMBLE_BLOWFISH;

// FILE *keyfile = NULL;
const char *keyfn = "keyfile";

void cryptopANT::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  int cnt = batch->cnt();
  if (bess::utils::scramble_init_from_file(keyfn, key_crypto, key_crypto,
                                           NULL) < 0) {
    fprintf(stderr, "Error: accessing keyfile '%s'\n", keyfn);
    exit(1);
  }

  for (int i = 0; i < cnt; i++) {
    bess::Packet *pkt = batch->pkts()[i];

    Ethernet *eth = pkt->head_data<Ethernet *>();
    Ipv4 *ip = reinterpret_cast<Ipv4 *>(eth + 1);

    // anonymize needs uint32
    uint32_t src, dst;
    src = ip->src.value();
    dst = ip->dst.value();

    // replace source and destination with CryptoPAn IPs
    ip->src = (be32_t)bess::utils::scramble_ip4(src, pass_bits4);
    ip->dst = (be32_t)bess::utils::scramble_ip4(dst, pass_bits4);
  }
  RunNextModule(ctx, batch);
}

ADD_MODULE(cryptopANT, "cryptopant",
           "anonymizes IP addresses using the CryptoPAn algorithm")