#include "lyra2z.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "sph_blake.h"
#include "lyra2.h"

#include "../miner.h"


void lyra2z_hash(void* output, const void* input)
{
	sph_blake256_context ctx_blake;

	uint32_t hashA[8], hashB[8];

	sph_blake256_set_rounds(14);
	sph_blake256_init(&ctx_blake);
	sph_blake256(&ctx_blake, input, 80);
	sph_blake256_close(&ctx_blake, hashA);
 
	LYRA2(hashB, 32, hashA, 32, hashA, 32, 8, 8, 8);
 
	memcpy(output, hashB, 32);
}

int scanhash_lyra2z(int thr_id, uint32_t *pdata, const uint32_t *ptarget, uint32_t max_nonce, uint64_t *hashes_done)
{
	int i;
	uint32_t _ALIGN(64) hash64[8];
	uint32_t _ALIGN(64) endiandata[20];

	const uint32_t Htarg = ptarget[7];
	const uint32_t first_nonce = pdata[19];

	uint32_t n = first_nonce;

	for (i=0; i < 19; i++) {
		be32enc(&endiandata[i], pdata[i]);
	}

	do {
		be32enc(&endiandata[19], n);
		lyra2z_hash(hash64, endiandata);
		if (hash64[7] < Htarg && fulltest(hash64, ptarget)) {
			*hashes_done = n - first_nonce + 1;
			pdata[19] = n;
			return true;
		}
		n++;

	} while (n < max_nonce && !work_restart[thr_id].restart);

	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;

	return 0;
}
