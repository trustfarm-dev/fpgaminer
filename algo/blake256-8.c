#include <string.h>
#include <stdint.h>
#include <memory.h>

#include "../miner.h"
#include "sph_blake.h"

extern void blake256_8_midstate(unsigned char *midstate, unsigned char *data);
extern void blake256_8_hash(unsigned char *hash, unsigned char *data);
extern int scanhash_blakecoin(int thr_id, uint32_t *pdata, const uint32_t *ptarget, uint32_t max_nonce, uint64_t *hashes_done);

void blake256_8_midstate(unsigned char *midstate, unsigned char *data)
{
	int i;
	uint32_t* m = (uint32_t*)midstate;
	sph_blake256_context ctx;
	
	sph_blake256_set_rounds(8);
	sph_blake256_init(&ctx);
	sph_blake256(&ctx, data, 80);
	
	memcpy(midstate, ctx.H, 32);
}

void blake256_8_hash(unsigned char *hash, unsigned char *data)
{
	sph_blake256_context ctx;
	unsigned char h[64];
	
	sph_blake256_set_rounds(8);
	sph_blake256_init(&ctx);
	sph_blake256(&ctx, data, 80);
	sph_blake256_close(&ctx, h);
	
	memcpy(hash, h, 32);
}

int scanhash_blake256_8(int thr_id, uint32_t *pdata, const uint32_t *ptarget, uint32_t max_nonce, uint64_t *hashes_done)
{
	int i;
	const uint32_t first_nonce = pdata[19];
	uint32_t HTarget = ptarget[7];

	uint32_t _ALIGN(32) hash[16];
	uint32_t _ALIGN(32) endiandata[20];

	uint32_t n = first_nonce;

	sph_blake256_context ctx;
	sph_blake256_context ctx_mid;
	
	// Change Endianess On Each 4 Byte Chunk
	swap_endian(endiandata, pdata, 80);
	
	sph_blake256_set_rounds(8);
	sph_blake256_init(&ctx);
	sph_blake256(&ctx, endiandata, 80);
	
	// Save Midstate
	memcpy(&ctx_mid, &ctx, sizeof(sph_blake256_context));
	
	do {
		be32enc(&endiandata[19], n);
		sph_blake256_close(&ctx, hash);

		if (hash[7] <= HTarget && fulltest(hash, ptarget)) {
			*hashes_done = n - first_nonce + 1;
			return true;
		}

		n++; pdata[19] = n;

		memcpy(&ctx, &ctx_mid, sizeof(sph_blake256_context));

	} while (n < max_nonce && !work_restart[thr_id].restart);

	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;
	return 0;
}
