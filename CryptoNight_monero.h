/* XMRig
 * Copyright 2010      Jeff Garzik <jgarzik@pobox.com>
 * Copyright 2012-2014 pooler      <pooler@litecoinpool.org>
 * Copyright 2014      Lucas Jones <https://github.com/lucasjones>
 * Copyright 2014-2016 Wolf9466    <https://github.com/OhGodAPet>
 * Copyright 2016      Jay D Dee   <jayddee246@gmail.com>
 * Copyright 2017-2018 XMR-Stak    <https://github.com/fireice-uk>, <https://github.com/psychocrypt>
 * Copyright 2018      Lee Clagett <https://github.com/vtnerd>
 * Copyright 2016-2018 XMRig       <https://github.com/xmrig>, <support@xmrig.com>
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __CRYPTONIGHT_MONERO_H__
#define __CRYPTONIGHT_MONERO_H__

#include <stdlib.h>

#define MONERO_V7 1

#if MONERO_V7

// VARIANT ALTERATIONS

#define VARIANT1_INIT() \
  if (VARIANT > 0 && len < 43) \
  { \
    fprintf(stderr, "Cryptonight variants need at least 43 bytes of data"); \
    exit(1); \
  } \
  const uint64_t tweak1_2 = VARIANT > 0 ? *(const uint64_t*)(((const uint8_t*)input)+35) ^ *((const uint64_t*)(ctx0->hash_state) + 24) : 0


#define VARIANT1_1(p) if(VARIANT){\
        const uint8_t tmp = (const uint8_t*)(p)[11]; \
        static const uint32_t table = 0x75310; \
        const uint8_t index = (((tmp >> 3) & 6) | (tmp & 1)) << 1; \
        ((uint8_t*)(p))[11] = tmp ^ ((table >> index) & 0x30);}

#define VARIANT1_2(p, part) if(VARIANT){\
        (p) ^= tweak1_2; }
#else
#define VARIANT1_INIT(part) 
#define VARIANT1_1(p)
#define VARIANT1_2(p, part)
#endif

#endif /* __CRYPTONIGHT_MONERO_H__ */
