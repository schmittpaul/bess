// Package: Crypto-PAn 1.0
// File: panonymizer.h
// Last Update: Aug 8, 2005
// Author: Jinliang Fan, David Stott

#ifndef BESS_UTILS_PANONYMIZER_H_
#define BESS_UTILS_PANONYMIZER_H_

#include "cryptop.h"

namespace bess {
namespace utils {

#define PA_MAX_KEYSIZE 32 /* 256 bit key */
#define PA_MAX_BLOCKSIZE PA_MAX_KEYSIZE

class PAnonymizer {  // Prefix-preserving anonymizer
 public:
  // Contructor need a 256-bit key
  // The first 128 bits of the key are used as the secret key for rijndael
  // cipher The second 128 bits of the key are used as the secret pad for
  // padding
  PAnonymizer(const u_int8_t* key);
  PAnonymizer(const char* ciphername /*="aes-128-ecb"*/, const u_int8_t* key);
  ~PAnonymizer();

 protected:
  Crypto m_crypto;  // cipher context
  size_t m_blocksize;
  u_int8_t* m_pad;  // secret pad

 public:
  u_int32_t anonymize(u_int32_t orig_addr);
  u_int32_t deanonymize(u_int32_t orig_addr);
  u_int32_t nonpa_deanonymize(u_int32_t fake_addr);
  u_int32_t nonpa_anonymize(u_int32_t orig_addr);
};

}  // namespace utils
}  // namespace bess

#endif  // BESS_UTILS_PANONYMIZER_H_