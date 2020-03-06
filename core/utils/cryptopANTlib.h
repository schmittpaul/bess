/* BESS version based on cryptopANT 1.2.1 (2019-09-30)
 * Modified by Paul Schmitt
 * Copyright (C) 2004-2018 by the University of Southern California
 * $Id: 58a4704e7a2580bed5f7eac76cd23b809dd558fa $
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
#ifndef BESS_UTILS_CRYPTOPANTLIB_H_
#define BESS_UTILS_CRYPTOPANTLIB_H_

#define ETHER_ADDR_LEN 6
#define ETHER_VLAN_LEN 2

//#define _XOR16(a, b, i)         (((uint16_t *)(a))[i] ^= ((uint16_t *)(b))[i])
//#define _XOR32(a, b, i)         (((uint32_t *)(a))[i] ^= ((uint32_t *)(b))[i])

#define SCRAMBLE_ETHER_ADDR(a)         \
  if (1) {                             \
    _XOR32(a, scramble_ether_addr, 0); \
    _XOR16(a, scramble_ether_addr, 2); \
  }

#define SCRAMBLE_ETHER_VLAN(v) ((v) ^= scramble_ether_vlan);

#define SCRAMBLE_RANDOM_DEV "/dev/urandom"

namespace bess {
namespace utils {

typedef enum {
  SCRAMBLE_NONE = 0x00,
  SCRAMBLE_MD5 = 0x01,
  SCRAMBLE_BLOWFISH = 0x02,
  SCRAMBLE_AES = 0x03,
  SCRAMBLE_SHA1 = 0x04
} scramble_crypt_t;

typedef struct {
  scramble_crypt_t c4;
  scramble_crypt_t c6;
  u_char *key;
  int klen;
  u_char *pad;
  int plen;
  u_char *mac;
  int mlen;
  u_char *iv;
  int ivlen;
} scramble_state_t;

scramble_crypt_t scramble_crypto_ip4(void);
scramble_crypt_t scramble_crypto_ip6(void);
scramble_crypt_t scramble_name2type(const char *);
const char *scramble_type2name(scramble_crypt_t);
int scramble_newkey(u_char *, uint);
int scramble_newpad(u_char *, uint);
int scramble_newmac(u_char *, uint);
int scramble_readstate(const char *, scramble_state_t *);
int scramble_savestate(const char *, const scramble_state_t *);
int scramble_init(const scramble_state_t *s);
int scramble_init_from_file(const char *, scramble_crypt_t, scramble_crypt_t,
                            int *);
uint32_t scramble_ip4(uint32_t, int);
uint32_t unscramble_ip4(uint32_t, int);
void scramble_ip6(struct in6_addr *, int);

}  // namespace utils
}  // namespace bess

#endif  // BESS_UTILS_CRYPTOPANTLIB_H_