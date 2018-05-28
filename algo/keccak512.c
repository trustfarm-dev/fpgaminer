#include "../miner.h"

#include <string.h>
#include <stdint.h>

#include "sph_keccak.h"

/*void keccak512_midstate(void *output, const void *input)
{
	sph_keccak_context keccak_ctx;

	sph_keccak512_init(&keccak_ctx);
	sph_keccak512(&keccak_ctx, input, 80);

	memcpy(output, &keccak_ctx.u, 200);
}*/

void keccak512_hash(void *output, const void *input)
{
	sph_keccak_context keccak_ctx;

	sph_keccak512_init(&keccak_ctx);
	sph_keccak512(&keccak_ctx, input, 80);
	sph_keccak512_close(&keccak_ctx, output);
}

int scanhash_keccak512(int thr_id, uint32_t *pdata, const uint32_t *ptarget, uint32_t max_nonce, uint64_t *hashes_done)
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
		keccak512_hash(hash64, endiandata);
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
