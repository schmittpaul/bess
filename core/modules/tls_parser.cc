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

#include "tls_parser.h"

#include <algorithm>
#include <tuple>

#include "../utils/checksum.h"
#include "../utils/ether.h"
#include "../utils/format.h"
#include "../utils/ip.h"
#include "../utils/tls.h"

#define SERVER_NAME_LEN 256
#define TLS_HEADER_LEN 5
#define TLS_HANDSHAKE 22  // 0x16
#define TLS_CLIENT_HELLO 1
#define TLS_SERVER_HELLO 2

#define OFFSET_HELLO_VERSION 9
#define OFFSET_SESSION_LENGTH 43
#define OFFSET_CIPHER_LIST 44

using bess::utils::be16_t;
using bess::utils::Ethernet;
using bess::utils::Ipv4;
using bess::utils::Tcp;
using bess::utils::Tls;

enum SSLVersions {
  SSLv30 = 0x000,
  TLSv10 = 0x001,
  TLSv11 = 0x002,
  TLSv12 = 0x003,
  TLSv13 = 0x004,
};

bool version_ok(uint8_t major, uint8_t minor) {
  if (major != 3)
    return false;

  switch (minor) {
    case SSLv30:
    case TLSv10:
    case TLSv11:
    case TLSv12:
    case TLSv13:
      return true;

    default:
      return false;
  }
}

static int parse_server_name_extension(const uint8_t *data, size_t data_len,
                                       char **hostname) {
  size_t pos = 2; /* skip server name list length */
  size_t len;

  while (pos + 3 < data_len) {
    len = ((size_t)data[pos + 1] << 8) + (size_t)data[pos + 2];

    if (pos + 3 + len > data_len)
      return -5;

    switch (data[pos]) { /* name type */
      case 0x00:         /* host_name */
        *hostname = (char *)malloc(len + 1);
        if (*hostname == NULL) {
          return -4;
        }

        strncpy(*hostname, (const char *)(data + pos + 3), len);

        (*hostname)[len] = '\0';

        return len;
      default:
        printf("Unknown server name extension name type: %" PRIu8, data[pos]);
    }
    pos += 3 + len;
  }
  /* Check we ended where we expected to */
  if (pos != data_len)
    return -5;

  return -2;
}

static int parse_extensions(const uint8_t *data, size_t data_len,
                            char **hostname) {
  size_t pos = 0;
  size_t len;

  /* Parse each 4 bytes for the extension header */
  while (pos + 4 <= data_len) {
    /* Extension Length */
    len = ((size_t)data[pos + 2] << 8) + (size_t)data[pos + 3];

    /* Check if it's a server name extension */
    if (data[pos] == 0x00 && data[pos + 1] == 0x00) {
      /* There can be only one extension of each type, so we break
         our state and move p to beinnging of the extension here */
      if (pos + 4 + len > data_len)
        return -5;
      return parse_server_name_extension(data + pos + 4, len, hostname);
    }
    pos += 4 + len; /* Advance to the next extension header */
  }
  /* Check we ended where we expected to */
  if (pos != data_len)
    return -5;

  return -2;
}

void TlsParser::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  int cnt = batch->cnt();

  for (int i = 0; i < cnt; i++) {
    size_t pos = TLS_HEADER_LEN;
    size_t len;
    char *hostname;

    bess::Packet *pkt = batch->pkts()[i];

    Ethernet *eth = pkt->head_data<Ethernet *>();
    Ipv4 *ip = reinterpret_cast<Ipv4 *>(eth + 1);

    if (ip->protocol != Ipv4::Proto::kTcp) {
      DropPacket(ctx, pkt);
      continue;
    }

    int ip_bytes = ip->header_length << 2;
    Tcp *tcp =
        reinterpret_cast<Tcp *>(reinterpret_cast<uint8_t *>(ip) + ip_bytes);

    int tcp_bytes = tcp->offset << 2;

    int size_payload = ip->length.value() - (ip_bytes + tcp_bytes);

    if (size_payload <
        OFFSET_CIPHER_LIST + 3) {  // at least one cipher + compression
      // printf("TLS handshake header too short: %d bytes\n", size_payload);
      DropPacket(ctx, pkt);
      continue;
    }

    Tls *tls =
        reinterpret_cast<Tls *>(reinterpret_cast<uint8_t *>(tcp) + tcp_bytes);

    if (tls->tls_content_type != TLS_HANDSHAKE) {
      // Not a TLS Handshake
      DropPacket(ctx, pkt);
      continue;
    }

    if (!version_ok(tls->tls_version_major, tls->tls_version_minor)) {
      // Not a TLS version that could have SNI
      DropPacket(ctx, pkt);
      continue;
    }

    uint8_t *tcp_payload = reinterpret_cast<uint8_t *>(tcp) + tcp_bytes;

    if (tcp_payload[pos] != TLS_CLIENT_HELLO) {
      // printf("CLIENT HELLO %d\n", tcp_payload[pos]);
      DropPacket(ctx, pkt);
      continue;
    }

    /* Skip past fixed length records:
   1	Handshake Type
   3	Length
   2	Version (again)
   32	Random
   to	Session ID Length
 */
    pos += 38;

    /* Session ID */
    if (pos + 1 > (unsigned)size_payload) {
      printf("SessionID quit");
      DropPacket(ctx, pkt);
      continue;
    }
    len = (size_t)tcp_payload[pos];
    pos += 1 + len;

    /* Cipher Suites */
    if (pos + 2 > (unsigned)size_payload) {
      DropPacket(ctx, pkt);
      continue;
    }

    len = ((size_t)tcp_payload[pos] << 8) + (size_t)tcp_payload[pos + 1];
    pos += 2 + len;

    /* Compression Methods */
    if (pos + 1 > (unsigned)size_payload) {
      DropPacket(ctx, pkt);
      continue;
    }
    len = (size_t)tcp_payload[pos];
    pos += 1 + len;

    if (pos == (unsigned)size_payload && tls->tls_version_major == 3 &&
        tls->tls_version_minor == 0) {
      // Received SSL 3.0 handshake without extensions
      DropPacket(ctx, pkt);
      continue;
    }

    /* Extensions */
    if (pos + 2 > (unsigned)size_payload) {
      DropPacket(ctx, pkt);
      continue;
    }
    len = ((size_t)tcp_payload[pos] << 8) + (size_t)tcp_payload[pos + 1];
    pos += 2;

    if (pos + len > (unsigned)size_payload) {
      DropPacket(ctx, pkt);
      continue;
    }
    int resp = parse_extensions(tcp_payload + pos, len, &hostname);
    if (resp > 0) {
      printf("HOSTNAME %s\n", hostname);
    }
    EmitPacket(ctx, pkt, 0);
  }
}

ADD_MODULE(TlsParser, "tls-parser", "Parse TLS headers")
