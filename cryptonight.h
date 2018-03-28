#ifndef CRYPTONIGHT_H
#define CRYPTONIGHT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

	typedef struct {
		uint8_t hash_state[224]; // Need only 200, explicit align
		uint8_t* long_state;
		uint8_t ctx_info[24]; //Use some of the extra memory for flags
	} cryptonight_ctx;

	typedef struct {
		const char* warning;
	} alloc_msg;
#define MEMORY  2097152

void cryptonight_hash(size_t ITERATIONS
	, size_t MEM
	, int SOFT_AES
	, int PREFETCH
	, int VARIANT
	, const void* input
	, size_t len
	, void* output
, cryptonight_ctx *ctx0);

void cryptonight_fast_hash(const char* input, char* output, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif
