#include "../miner.h"

#include <string.h>
#include <stdint.h>

#include "sph_blake.h"
#include "sph_groestl.h"
#include "sph_jh.h"
#include "sph_keccak.h"
#include "sph_skein.h"

void nist5_hash(void *output, const void *input)
{
	uint32_t hash[16];

    sph_blake512_context    blake1;
    sph_blake512_init(&blake1);
	sph_blake512 (&blake1, input, 80);
    sph_blake512_close (&blake1, hash);      

    sph_groestl512_context  groestl1;
    sph_groestl512_init(&groestl1);   
    sph_groestl512 (&groestl1, hash, 64); 
    sph_groestl512_close(&groestl1, hash);

    sph_jh512_context       jh1;
    sph_jh512_init(&jh1);
	sph_jh512 (&jh1, hash, 64); 
    sph_jh512_close(&jh1, hash);

    sph_keccak512_context   keccak1;
    sph_keccak512_init(&keccak1);
	sph_keccak512 (&keccak1, hash, 64); 
    sph_keccak512_close(&keccak1, hash);

    sph_skein512_context    skein1;
    sph_skein512_init(&skein1);   
	sph_skein512 (&skein1, hash, 64); 
    sph_skein512_close(&skein1, hash);

	memcpy(output, hash, 32);
}

int scanhash_nist5(int thr_id, uint32_t *pdata, const uint32_t *ptarget, uint32_t max_nonce, uint64_t *hashes_done)
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
		nist5_hash(hash64, endiandata);
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
