#include "../miner.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "sph_groestl.h"
#include "sha2.h"

void myriadhash(void *output, const void *input)
{
	uint32_t _ALIGN(32) hash[16];
	unsigned char hash2[32];
	sph_groestl512_context ctx;
	sha256_ctx sha_ctx;

	sph_groestl512_init(&ctx);
	sph_groestl512(&ctx, input, 80);
	sph_groestl512_close(&ctx, hash);

    sha256_init(&sha_ctx);
    sha256_update(&sha_ctx, (unsigned char*)hash, 64);
    sha256_final(&sha_ctx, hash2);

	memcpy(output, hash2, 32);
}

int scanhash_myriad(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
	uint32_t max_nonce, uint64_t *hashes_done)
{
	uint32_t _ALIGN(64) endiandata[20];
	const uint32_t first_nonce = pdata[19];
	uint32_t nonce = first_nonce;

	int k;
	for (k=0; k < 20; k++)
		be32enc(&endiandata[k], ((uint32_t*)pdata)[k]);

	do {
		const uint32_t Htarg = ptarget[7];
		uint32_t hash[8];
		be32enc(&endiandata[19], nonce);
		myriadhash(hash, endiandata);

		if (hash[7] <= Htarg && fulltest(hash, ptarget)) {
			pdata[19] = nonce;
			*hashes_done = pdata[19] - first_nonce;
			return 1;
		}
		nonce++;

	} while (nonce < max_nonce && !work_restart[thr_id].restart);

	pdata[19] = nonce;
	*hashes_done = pdata[19] - first_nonce + 1;
	return 0;
}
