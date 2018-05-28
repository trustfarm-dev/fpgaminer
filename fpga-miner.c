/*
 * Copyright 2010 Jeff Garzik
 * Copyright 2012-2014 pooler
 * Copyright 2014 Lucas Jones
 * Copyright 2014 Tanguy Pruvot
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#include <signal.h>

#include <curl/curl.h>
#include <jansson.h>

#include <getopt.h>

#ifdef _MSC_VER
#include <windows.h>
#include <stdint.h>
#else
#include <errno.h>
#if HAVE_SYS_SYSCTL_H
#include <sys/types.h>
#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#include <sys/sysctl.h>
#endif
#endif

#ifndef WIN32
#include <sys/resource.h>
#endif

#include "miner.h"

#ifdef WIN32
#include "compat/winansi.h"
#endif
#ifdef _MSC_VER
#include <Mmsystem.h>
#pragma comment(lib, "winmm.lib")
#endif

#include <stdint.h>

#include <fpga_pci.h>
#include <fpga_mgmt.h>
#include <utils/lcd.h>


static uint16_t pci_vendor_id = 0x1D0F;
static uint16_t pci_device_id = 0xF000;
int pci_test(int slot, int pf_id, int bar_id);
int check_afi_ready(int slot);


int pci_test(int slot_id, int pf_id, int bar_id) {
	int i, rc;
	uint32_t value = 0x00000000;
	uint64_t addr = 0x500;
	pci_bar_handle_t pci_bar_handle = PCI_BAR_HANDLE_INIT;

	// attach to the fpga, with a pci_bar_handle out param
	// To attach to multiple slots or BARs, call this function multiple times,
	// saving the pci_bar_handle to specify which address space to interact with in
	// other API calls.
	// This function accepts the slot_id, physical function, and bar number
	rc = fpga_pci_attach(slot_id, pf_id, bar_id, 0, &pci_bar_handle);

	// Send empty value to address 0x500 to trigger FPGA to send back a result...this is just a dummy test to show connectivity
	printf("Running connectivity test\n");
	rc = fpga_pci_poke(pci_bar_handle, addr, value);

	// Display value returned from FPGA
	rc = fpga_pci_peek(pci_bar_handle, addr, &value);
	printf("FPGA returned 0x%x from address 0x%x\n", value, addr);

	// Create dummy Block Header data
	unsigned char b[] = { 0x02, 0x04, 0x00, 0x00, 0x13, 0xd7, 0xa7, 0x79, 0x94, 0x5e, 0xf7, 0x76, 0xe2, 0x5a, 0x7a, 0xec, 0xf8, 0xcc, 0x45, 0xe9, 0x7b, 0xac, 0xb8, 0x01, 0xeb, 0xb3, 0x90, 0x54, 0x5a, 0x42, 0xee, 0x32, 0xd0, 0x64, 0xd9, 0x5b, 0xcf, 0x21, 0x57, 0xa3, 0xe0, 0x19, 0x12, 0xbe, 0xa9, 0xc7, 0x35, 0x65, 0xf7, 0x45, 0x09, 0xde, 0xfd, 0x41, 0x92, 0x4e, 0x6d, 0xd7, 0xf2, 0x3b, 0xa7, 0x7d, 0xa9, 0x6c, 0xa6, 0xc8, 0x42, 0x5b, 0x06, 0xb1, 0x53, 0x53, 0x1e, 0xc1, 0x00, 0x1c, 0xFF, 0x00, 0x00, 0x00 };
	printf("Block Header: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n", b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7],b[8],b[9],b[10],b[11],b[12],b[13],b[14],b[15],b[16],b[17],b[18],b[19],b[20],b[21],b[22],b[23],b[24],b[25],b[26],b[27],b[28],b[29],b[30],b[31],b[32],b[33],b[34],b[35],b[36],b[37],b[38],b[39],b[40],b[41],b[42],b[43],b[44],b[45],b[46],b[47],b[48],b[49],b[50],b[51],b[52],b[53],b[54],b[55],b[56],b[57],b[58],b[59],b[60],b[61],b[62],b[63], b[64],b[65],b[66],b[67],b[68],b[69],b[70],b[71],b[72],b[73],b[74],b[75],b[76],b[77],b[78],b[79] );
	uint32_t *b32 = (uint32_t *)b;

	// Send Block Header data to FPGA
	// Break Block Header into 32bit chunks and pass to pci register addresses offset by 4 bytes each time
	for (i = 0; i < 20; i++) {
		addr += 4;
//		rc = fpga_pci_poke(pci_bar_handle, addr, b32[i]);
		rc = fpga_pci_poke(pci_bar_handle, addr, swab32(b32[i]));
	}

	printf("Block Header sent to FPGA.\n");

	sleep(1);

	// Check for result returned from FPGA
	addr = UINT64_C(0x554);
	value = 0x11111111;
	rc = fpga_pci_peek(pci_bar_handle, addr, &value);
	printf("FPGA returned 0x%x from address 0x%x\n", value, addr);

	// Send empty value to address 0x530 to trigger FPGA to send back a result...this is just a dummy test to show connectivity
	printf("Running connectivity test\n");
	addr = UINT64_C(0x558);
	value = 0x22222222;
	rc = fpga_pci_poke(pci_bar_handle, addr, value);

	// Display value returned from FPGA
	rc = fpga_pci_peek(pci_bar_handle, addr, &value);
	printf("FPGA returned 0x%x from address 0x%x\n", value, addr);

	// Send Block Header data to FPGA
	// Break Block Header into 32bit chunks and pass to pci register addresses offset by 4 bytes each time
//	printf("\nDumping Block Header stored in FPGA...\n\n");
//	addr = UINT64_C(0x000);
//	value = 0x33333333;
//	for (i = 0; i < 20; i++) {
//		rc = fpga_pci_peek(pci_bar_handle, addr, &value);
//		printf("FPGA returned 0x%x from address 0x%x\n", value, addr);
//		addr += 4;
//	}

	printf("\nDone.\n");

	exit(0);
	
}

int check_afi_ready(int slot_id) {
    struct fpga_mgmt_image_info info = {0}; 
    int rc;

    rc = fpga_mgmt_describe_local_image(slot_id, &info,0);
    fail_on(rc, out, "Unable to get AFI information from slot %d. Are you running as root?",slot_id);

    if (info.status != FPGA_STATUS_LOADED) {
        rc = 1;
        fail_on(rc, out, "AFI in Slot %d is not in READY state !", slot_id);
    }

    printf("AFI PCI  Vendor ID: 0x%x, Device ID 0x%x\n",
        info.spec.map[FPGA_APP_PF].vendor_id,
        info.spec.map[FPGA_APP_PF].device_id);

    if (info.spec.map[FPGA_APP_PF].vendor_id != pci_vendor_id ||
        info.spec.map[FPGA_APP_PF].device_id != pci_device_id) {
        printf("AFI does not show expected PCI vendor id and device ID. If the AFI "
               "was just loaded, it might need a rescan. Rescanning now.\n");

        rc = fpga_pci_rescan_slot_app_pfs(slot_id);
        fail_on(rc, out, "Unable to update PF for slot %d",slot_id);
        rc = fpga_mgmt_describe_local_image(slot_id, &info,0);
        fail_on(rc, out, "Unable to get AFI information from slot %d",slot_id);

        printf("AFI PCI  Vendor ID: 0x%x, Device ID 0x%x\n",
            info.spec.map[FPGA_APP_PF].vendor_id,
            info.spec.map[FPGA_APP_PF].device_id);

        if (info.spec.map[FPGA_APP_PF].vendor_id != pci_vendor_id ||
             info.spec.map[FPGA_APP_PF].device_id != pci_device_id) {
            rc = 1;
            fail_on(rc, out, "The PCI vendor id and device of the loaded AFI are not "
                             "the expected values.");
        }
    }
    
    return rc;

out:
    return 1;
}





#define LP_SCANTIME		60

enum workio_commands {
	WC_GET_WORK,
	WC_SUBMIT_WORK,
};

struct workio_cmd {
	enum workio_commands cmd;
	struct thr_info *thr;
	union {
		struct work *work;
	} u;
};

enum algos {
	ALGO_DMD_GR,      // Groestl (double SHA256 on merkle)
	ALGO_GROESTL,     // Groestl (single SHA256 on merkle)
	ALGO_MYR_GR,      // Myriad Groestl (double SHA256 on merkle)
	ALGO_BLAKECOIN,   // Blake 256 - 8 Rounds (single SHA256 on merkle)
	ALGO_VCASH,       // Blake 256 - 8 Rounds (double SHA256 on merkle)
	ALGO_BLAKE2S,     // Blake2s
	ALGO_KECCAK256,	  // KECCAK256
	ALGO_KECCAK512,   // Keccak512
	ALGO_LYRA2REV2,   // Lyra2REv2
	ALGO_LYRA2Z,      // Lyra2Z
	ALGO_NIST5,       // NIST5
	ALGO_COUNT
};

static const char *algo_names[] = {
	"dmd-gr",
	"groestl",
	"myr-gr",
	"blakecoin",
	"vcash",
	"blake2s",
	"keccak256",
	"keccak512",
	"lyra2rev2",
	"lyra2z",
	"nist5",
	"\0"
};

bool opt_debug = false;
bool opt_protocol = false;
bool opt_redirect = true;
bool opt_extranonce = true;
bool want_longpoll = true;
bool have_longpoll = false;
bool have_gbt = true;
bool allow_getwork = true;
bool want_stratum = true;
bool have_stratum = false;
bool allow_mininginfo = true;
bool use_colors = true;
bool opt_quiet = false;
static int opt_retries = -1;
static int opt_fail_pause = 10;
int opt_timeout = 300;
static int opt_scantime = 5;
static const bool opt_time = true;
static enum algos opt_algo = ALGO_GROESTL;
int opt_n_threads = 0;
int opt_affinity = -1;
int opt_priority = 0;
int num_cpus;
char *rpc_url;
char *rpc_userpass;
char *rpc_user, *rpc_pass;
char *short_url = NULL;
static unsigned char pk_script[25] = { 0 };
static size_t pk_script_size = 0;
static char coinbase_sig[101] = { 0 };
char *opt_cert;
char *opt_proxy;
long opt_proxy_type;
struct thr_info *thr_info;
int work_thr_id;
int longpoll_thr_id = -1;
int stratum_thr_id = -1;
int api_thr_id = -1;
bool stratum_need_reset = false;
struct work_restart *work_restart = NULL;
struct stratum_ctx stratum;
bool jsonrpc_2 = false;
char rpc2_id[64] = "";
char *rpc2_blob = NULL;
size_t rpc2_bloblen = 0;
uint32_t rpc2_target = 0;
char *rpc2_job_id = NULL;
bool aes_ni_supported = false;
double opt_diff_factor = 1.0;
pthread_mutex_t rpc2_job_lock;
pthread_mutex_t rpc2_login_lock;
pthread_mutex_t applog_lock;
pthread_mutex_t stats_lock;

uint32_t accepted_count = 0L;
uint32_t rejected_count = 0L;
double *thr_hashrates;
uint64_t global_hashrate = 0;
double stratum_diff = 0.;
double net_diff = 0.;
double net_hashrate = 0.;
uint64_t net_blocks = 0;

uint32_t opt_work_size = 0; /* default */
char *opt_api_allow = NULL;
int opt_api_remote = 0;
int opt_api_listen = 4048; /* 0 to disable */


//
// Begin FPGA
//


bool opt_use_cpu = false;
bool opt_use_serial = false;
bool opt_use_ztex = false;
bool opt_auto_freq = false;
bool opt_fpga_summary = false;
bool opt_firmware = false;

int g_miner_count;
int g_fpga_count;
int g_serial_fpga_count;
int g_ztex_fpga_count;
int g_serial_device_count;

int g_ztex_freq = 24;	// Default = 100 Mhz
int g_fpga_work_len = 80;
bool g_fpga_use_midstate = false;

int g_block_count = 0;
double g_net_diff = 0.0;

int g_serial_device_count;
char* serial_fpga_list[MAX_SERIAL_DEVICES];
struct libztex_device *ztex_info;

struct timeval g_miner_start_time;

//
// End FPGA
//


static char const usage[] = "\
Usage: " PACKAGE_NAME " [OPTIONS]\n\
Options:\n\
  -a, --algo <algo>          The mining algorithm to use\n\
                               blake2s      Blake2s\n\
                               blakecoin    Blake256 - 8 Rounds\n\
                               dmd-gr       Diamond-Groestl\n\
                               groestl      GroestlCoin\n\
                               keccak256    Keccak256\n\
                               keccak512    Keccak512\n\
                               lyra2rev2    Lyra2REv2\n\
                               lyra2z       Lyra2Z\n\
                               myr-gr       Myriad-Groestl\n\
                               nist5        NIST5\n\
                               vcash        Blake256 - 8 Rounds\n\
  -o, --url=URL              URL of mining server\n\
  -O, --userpass <u:p>       Username:password pair for mining server\n\
  -u, --user <username>      Username for mining server\n\
  -p, --pass <password>      Password for mining server\n\
      --cert <file>          Certificate for mining server using SSL\n\
  -x, --proxy [PROTOCOL://]HOST[:PORT]  connect through a proxy\n\
  -t, --threads <n>          Number of miner threads (Default: Number of CPUs)\n\
  -r, --retries <n>          Number of times to retry if a network call fails\n\
                             (Default: Retry indefinitely)\n\
  -R, --retry-pause <n>      Time to pause between retries (Default: 30 sec)\n\
  -T, --timeout <n>          Timeout for longpoll and stratum (Default: 300 sec)\n\
  -s, --scan-time <n>        Max time to scan work for nonces (Default: 5 sec)\n\
  -S, --scan-serial          Serial port of Serial FPGA, (\\\\.\\COM1,\\\\.\\COM2,etc)\n\
  -f, --diff-factor          Divide target diff by this factor (Default: 1.0)\n\
  -m, --diff-multiplier      Multiply target diff by this factor (Default: 1.0)\n\
      --coinbase-addr <addr> Payout address for solo mining\n\
      --coinbase-sig <text>  Data to insert in the coinbase when possible\n\
      --no-longpoll          Disable long polling support\n\
      --no-getwork           Disable getwork support\n\
      --no-gbt               Disable getblocktemplate support\n\
      --no-stratum           Disable X-Stratum support\n\
      --no-extranonce        Disable Stratum extranonce support\n\
      --no-redirect          Ignore request to change URL of the mining server\n\
  -q, --quiet                Display minimal output\n\
      --no-color             Don't display colored output\n\
  -D, --debug                Display debug output\n\
  -P, --protocol-dump        Display dump of protocol-level activities\n\
      --cpu-affinity         Set process affinity to cpu core(s)\n\
      --cpu-priority         Set process priority (default: 0 idle to 5 highest)\n\
  -b, --api-bind             IP/Port for the miner API (default: 127.0.0.1:4048)\n\
      --api-remote           Allow remote control\n\
  -c, --config <file>        Use JSON-formated configuration file\n\
  -C, --cpu                  Use CPU for mining\n\
  -V, --version              Display version information and exit\n\
  -z, --ztex <freqency>      Use ZTEX FPGA for mining (Clock frequency in Mhz)\n\
      --auto-freq            Automatically adjust ZTEX chip frequency\n\
  -F, --firmware             Reload firmware on ZTEX FPGAs\n\
  -h, --help                 Display this help text and exit\n\n\
Options while mining ----------------------------------------------------------\n\n\
   s + <enter>               Display mining summary\n\
   f + <enter>               Display fpga summary\n\
   d + <enter>               Toggle Debug mode\n\
   q + <enter>               Toggle Quite mode\n\
";


static char const short_options[] =
	"a:b:c:C:D:f:F:h:m:p:Px:q:r:R:s:S:t:T:o:u:O:V:z";

static struct option const options[] = {
	{ "algo", 1, NULL, 'a' },
	{ "api-bind", 1, NULL, 'b' },
	{ "api-remote", 0, NULL, 1030 },
	{ "cert", 1, NULL, 1001 },
	{ "coinbase-addr", 1, NULL, 1013 },
	{ "coinbase-sig", 1, NULL, 1015 },
	{ "config", 1, NULL, 'c' },
	{ "cpu", 0, NULL, 'C' },
	{ "cpu-affinity", 1, NULL, 1020 },
	{ "cpu-priority", 1, NULL, 1021 },
	{ "no-color", 0, NULL, 1002 },
	{ "debug", 0, NULL, 'D' },
	{ "diff-factor", 1, NULL, 'f' },
	{ "diff-multiplier", 1, NULL, 'm' },
	{ "help", 0, NULL, 'h' },
	{ "no-gbt", 0, NULL, 1011 },
	{ "no-getwork", 0, NULL, 1010 },
	{ "no-longpoll", 0, NULL, 1003 },
	{ "no-redirect", 0, NULL, 1009 },
	{ "no-stratum", 0, NULL, 1007 },
	{ "no-extranonce", 0, NULL, 1012 },
	{ "pass", 1, NULL, 'p' },
	{ "protocol", 0, NULL, 'P' },
	{ "protocol-dump", 0, NULL, 'P' },
	{ "proxy", 1, NULL, 'x' },
	{ "quiet", 0, NULL, 'q' },
	{ "retries", 1, NULL, 'r' },
	{ "retry-pause", 1, NULL, 'R' },
	{ "scan-time", 1, NULL, 's' },
	{ "scan-serial", 1, NULL, 'S' },
	{ "threads", 1, NULL, 't' },
	{ "timeout", 1, NULL, 'T' },
	{ "url", 1, NULL, 'o' },
	{ "user", 1, NULL, 'u' },
	{ "userpass", 1, NULL, 'O' },
	{ "ztex", 1, NULL, 'z' },
	{ "auto-freq", 0, NULL, 1004 },
	{ "firmware", 0, NULL, 'F' },
	{ "version", 0, NULL, 'V' },
	{ 0, 0, 0, 0 }
};

static struct work g_work = {{ 0 }};
static time_t g_work_time = 0;
static pthread_mutex_t g_work_lock;
static bool submit_old = false;
static char *lp_id;

static void workio_cmd_free(struct workio_cmd *wc);


#ifdef __linux /* Linux specific policy and affinity management */
#include <sched.h>

static inline void drop_policy(void)
{
	struct sched_param param;
	param.sched_priority = 0;
#ifdef SCHED_IDLE
	if (unlikely(sched_setscheduler(0, SCHED_IDLE, &param) == -1))
#endif
#ifdef SCHED_BATCH
		sched_setscheduler(0, SCHED_BATCH, &param);
#endif
}

#ifdef __BIONIC__
#define pthread_setaffinity_np(tid,sz,s) {} /* only do process affinity */
#endif

static void affine_to_cpu_mask(int id, uint8_t mask) {
	cpu_set_t set;
	CPU_ZERO(&set);
	uint8_t i;
	for ( i = 0; i < num_cpus; i++) {
		// cpu mask
		if (mask & (1<<i)) { CPU_SET(i, &set); }
	}
	if (id == -1) {
		// process affinity
		sched_setaffinity(0, sizeof(&set), &set);
	} else {
		// thread only
		pthread_setaffinity_np(thr_info[id].pth, sizeof(&set), &set);
	}
}

#elif defined(WIN32) /* Windows */
static inline void drop_policy(void) { }
static void affine_to_cpu_mask(int id, uint8_t mask) {
	if (id == -1)
		SetProcessAffinityMask(GetCurrentProcess(), mask);
	else
		SetThreadAffinityMask(GetCurrentThread(), mask);
}
#else
static inline void drop_policy(void) { }
static void affine_to_cpu_mask(int id, uint8_t mask) { }
#endif

void get_currentalgo(char* buf, int sz)
{
	snprintf(buf, sz, "%s", algo_names[opt_algo]);
}

void proper_exit(int reason)
{
	exit(reason);
}

static inline void work_free(struct work *w)
{
	if (w->txs) free(w->txs);
	if (w->workid) free(w->workid);
	if (w->job_id) free(w->job_id);
	if (w->xnonce2) free(w->xnonce2);
}

static inline void work_copy(struct work *dest, const struct work *src)
{
	memcpy(dest, src, sizeof(struct work));
	if (src->txs)
		dest->txs = strdup(src->txs);
	if (src->workid)
		dest->workid = strdup(src->workid);
	if (src->job_id)
		dest->job_id = strdup(src->job_id);
	if (src->xnonce2) {
		dest->xnonce2 = (uchar*) malloc(src->xnonce2_len);
		memcpy(dest->xnonce2, src->xnonce2, src->xnonce2_len);
	}
}

static bool work_decode(const json_t *val, struct work *work)
{
	int i;
	int data_size = sizeof(work->data), target_size = sizeof(work->target);
	int adata_sz = ARRAY_SIZE(work->data), atarget_sz = ARRAY_SIZE(work->target);

	if (jsonrpc_2) {
		return rpc2_job_decode(val, work);
	}

	if (unlikely(!jobj_binary(val, "data", work->data, data_size))) {
		applog(LOG_ERR, "JSON invalid data");
		goto err_out;
	}
	if (unlikely(!jobj_binary(val, "target", work->target, target_size))) {
		applog(LOG_ERR, "JSON invalid target");
		goto err_out;
	}

	for (i = 0; i < adata_sz; i++)
		work->data[i] = le32dec(work->data + i);

	for (i = 0; i < atarget_sz; i++)
		work->target[i] = le32dec(work->target + i);

	return true;

err_out:
	return false;
}

// good alternative for wallet mining, difficulty and net hashrate
static const char *info_req =
"{\"method\": \"getmininginfo\", \"params\": [], \"id\":8}\r\n";

static bool get_mininginfo(CURL *curl, struct work *work)
{
	if (have_stratum || !allow_mininginfo)
		return false;

	int curl_err = 0;
	json_t *val = json_rpc_call(curl, rpc_url, rpc_userpass, info_req, &curl_err, 0);

	if (!val && curl_err == -1) {
		allow_mininginfo = false;
		if (opt_debug) {
			applog(LOG_DEBUG, "getmininginfo not supported");
		}
		return false;
	}
	else {
		json_t *res = json_object_get(val, "result");
		// "blocks": 491493 (= current work height - 1)
		// "difficulty": 0.99607860999999998
		// "networkhashps": 56475980
		if (res) {
			json_t *key = json_object_get(res, "difficulty");
			if (key && json_is_real(key)) {
				net_diff = json_real_value(key);
			}
			key = json_object_get(res, "networkhashps");
			if (key && json_is_integer(key)) {
				net_hashrate = (double) json_integer_value(key);
			}
			key = json_object_get(res, "blocks");
			if (key && json_is_integer(key)) {
				net_blocks = json_integer_value(key);
			}
			if (!work->height) {
				// complete missing data from getwork
				work->height = (uint32_t) net_blocks + 1;
				if (work->height > g_work.height) {
					restart_threads();
					if (!opt_quiet) {
						char netinfo[64] = { 0 };
						char srate[32] = { 0 };
						sprintf(netinfo, "diff %.2f", net_diff);
						if (net_hashrate) {
							format_hashrate(net_hashrate, srate);
							strcat(netinfo, ", net ");
							strcat(netinfo, srate);
						}
						applog(LOG_BLUE, "%s block %d, %s",
							algo_names[opt_algo], work->height, netinfo);
					}
				}
			}
		}
	}
	json_decref(val);
	return true;
}

#define BLOCK_VERSION_CURRENT 3

static bool gbt_work_decode(const json_t *val, struct work *work)
{
	int i, n;
	uint32_t version, curtime, bits;
	uint32_t prevhash[8];
	uint32_t target[8];
	int cbtx_size;
	uchar *cbtx = NULL;
	int tx_count, tx_size;
	uchar txc_vi[9];
	uchar(*merkle_tree)[32] = NULL;
	bool coinbase_append = false;
	bool submit_coinbase = false;
	bool version_force = false;
	bool version_reduce = false;
	json_t *tmp, *txa;
	bool rc = false;

	tmp = json_object_get(val, "mutable");
	if (tmp && json_is_array(tmp)) {
		n = (int) json_array_size(tmp);
		for (i = 0; i < n; i++) {
			const char *s = json_string_value(json_array_get(tmp, i));
			if (!s)
				continue;
			if (!strcmp(s, "coinbase/append"))
				coinbase_append = true;
			else if (!strcmp(s, "submit/coinbase"))
				submit_coinbase = true;
			else if (!strcmp(s, "version/force"))
				version_force = true;
			else if (!strcmp(s, "version/reduce"))
				version_reduce = true;
		}
	}

	tmp = json_object_get(val, "height");
	if (!tmp || !json_is_integer(tmp)) {
		applog(LOG_ERR, "JSON invalid height");
		goto out;
	}
	work->height = (int) json_integer_value(tmp);
	applog(LOG_BLUE, "Current block is %d", work->height);

	tmp = json_object_get(val, "version");
	if (!tmp || !json_is_integer(tmp)) {
		applog(LOG_ERR, "JSON invalid version");
		goto out;
	}
	version = (uint32_t) json_integer_value(tmp);
	if ((version & 0xffU) > BLOCK_VERSION_CURRENT) {
		if (version_reduce) {
			version = (version & ~0xffU) | BLOCK_VERSION_CURRENT;
		} else if (have_gbt && allow_getwork && !version_force) {
			applog(LOG_DEBUG, "Switching to getwork, gbt version %d", version);
			have_gbt = false;
			goto out;
		} else if (!version_force) {
			applog(LOG_ERR, "Unrecognized block version: %u", version);
			goto out;
		}
	}

	if (!jobj_binary(val, "previousblockhash", prevhash, sizeof(prevhash))) {
		applog(LOG_ERR, "JSON invalid previousblockhash");
		goto out;
	}

	tmp = json_object_get(val, "curtime");
	if (!tmp || !json_is_integer(tmp)) {
		applog(LOG_ERR, "JSON invalid curtime");
		goto out;
	}
	curtime = (uint32_t) json_integer_value(tmp);

	if (!jobj_binary(val, "bits", &bits, sizeof(bits))) {
		applog(LOG_ERR, "JSON invalid bits");
		goto out;
	}

	/* find count and size of transactions */
	txa = json_object_get(val, "transactions");
	if (!txa || !json_is_array(txa)) {
		applog(LOG_ERR, "JSON invalid transactions");
		goto out;
	}
	tx_count = (int) json_array_size(txa);
	tx_size = 0;
	for (i = 0; i < tx_count; i++) {
		const json_t *tx = json_array_get(txa, i);
		const char *tx_hex = json_string_value(json_object_get(tx, "data"));
		if (!tx_hex) {
			applog(LOG_ERR, "JSON invalid transactions");
			goto out;
		}
		tx_size += (int) (strlen(tx_hex) / 2);
	}

	/* build coinbase transaction */
	tmp = json_object_get(val, "coinbasetxn");
	if (tmp) {
		const char *cbtx_hex = json_string_value(json_object_get(tmp, "data"));
		cbtx_size = cbtx_hex ? (int) strlen(cbtx_hex) / 2 : 0;
		cbtx = (uchar*) malloc(cbtx_size + 100);
		if (cbtx_size < 60 || !hex2bin(cbtx, cbtx_hex, cbtx_size)) {
			applog(LOG_ERR, "JSON invalid coinbasetxn");
			goto out;
		}
	} else {
		int64_t cbvalue;
		if (!pk_script_size) {
			if (allow_getwork) {
				applog(LOG_INFO, "No payout address provided, switching to getwork");
				have_gbt = false;
			} else
				applog(LOG_ERR, "No payout address provided");
			goto out;
		}
		tmp = json_object_get(val, "coinbasevalue");
		if (!tmp || !json_is_number(tmp)) {
			applog(LOG_ERR, "JSON invalid coinbasevalue");
			goto out;
		}
		cbvalue = (int64_t) (json_is_integer(tmp) ? json_integer_value(tmp) : json_number_value(tmp));
		cbtx = (uchar*) malloc(256);
		le32enc((uint32_t *)cbtx, 1); /* version */
		cbtx[4] = 1; /* in-counter */
		memset(cbtx+5, 0x00, 32); /* prev txout hash */
		le32enc((uint32_t *)(cbtx+37), 0xffffffff); /* prev txout index */
		cbtx_size = 43;
		/* BIP 34: height in coinbase */
		for (n = work->height; n; n >>= 8)
			cbtx[cbtx_size++] = n & 0xff;
		cbtx[42] = cbtx_size - 43;
		cbtx[41] = cbtx_size - 42; /* scriptsig length */
		le32enc((uint32_t *)(cbtx+cbtx_size), 0xffffffff); /* sequence */
		cbtx_size += 4;
		cbtx[cbtx_size++] = 1; /* out-counter */
		le32enc((uint32_t *)(cbtx+cbtx_size), (uint32_t)cbvalue); /* value */
		le32enc((uint32_t *)(cbtx+cbtx_size+4), cbvalue >> 32);
		cbtx_size += 8;
		cbtx[cbtx_size++] = (uint8_t) pk_script_size; /* txout-script length */
		memcpy(cbtx+cbtx_size, pk_script, pk_script_size);
		cbtx_size += (int) pk_script_size;
		le32enc((uint32_t *)(cbtx+cbtx_size), 0); /* lock time */
		cbtx_size += 4;
		coinbase_append = true;
	}
	if (coinbase_append) {
		unsigned char xsig[100];
		int xsig_len = 0;
		if (*coinbase_sig) {
			n = (int) strlen(coinbase_sig);
			if (cbtx[41] + xsig_len + n <= 100) {
				memcpy(xsig+xsig_len, coinbase_sig, n);
				xsig_len += n;
			} else {
				applog(LOG_WARNING, "Signature does not fit in coinbase, skipping");
			}
		}
		tmp = json_object_get(val, "coinbaseaux");
		if (tmp && json_is_object(tmp)) {
			void *iter = json_object_iter(tmp);
			while (iter) {
				unsigned char buf[100];
				const char *s = json_string_value(json_object_iter_value(iter));
				n = s ? (int) (strlen(s) / 2) : 0;
				if (!s || n > 100 || !hex2bin(buf, s, n)) {
					applog(LOG_ERR, "JSON invalid coinbaseaux");
					break;
				}
				if (cbtx[41] + xsig_len + n <= 100) {
					memcpy(xsig+xsig_len, buf, n);
					xsig_len += n;
				}
				iter = json_object_iter_next(tmp, iter);
			}
		}
		if (xsig_len) {
			unsigned char *ssig_end = cbtx + 42 + cbtx[41];
			int push_len = cbtx[41] + xsig_len < 76 ? 1 :
			               cbtx[41] + 2 + xsig_len > 100 ? 0 : 2;
			n = xsig_len + push_len;
			memmove(ssig_end + n, ssig_end, cbtx_size - 42 - cbtx[41]);
			cbtx[41] += n;
			if (push_len == 2)
				*(ssig_end++) = 0x4c; /* OP_PUSHDATA1 */
			if (push_len)
				*(ssig_end++) = xsig_len;
			memcpy(ssig_end, xsig, xsig_len);
			cbtx_size += n;
		}
	}

	n = varint_encode(txc_vi, 1 + tx_count);
	work->txs = (char*) malloc(2 * (n + cbtx_size + tx_size) + 1);
	bin2hex(work->txs, txc_vi, n);
	bin2hex(work->txs + 2*n, cbtx, cbtx_size);

	/* generate merkle root */
	merkle_tree = (uchar(*)[32]) calloc(((1 + tx_count + 1) & ~1), 32);
	sha256d(merkle_tree[0], cbtx, cbtx_size);
	for (i = 0; i < tx_count; i++) {
		tmp = json_array_get(txa, i);
		const char *tx_hex = json_string_value(json_object_get(tmp, "data"));
		const int tx_size = tx_hex ? (int) (strlen(tx_hex) / 2) : 0;
		unsigned char *tx = (uchar*) malloc(tx_size);
		if (!tx_hex || !hex2bin(tx, tx_hex, tx_size)) {
			applog(LOG_ERR, "JSON invalid transactions");
			free(tx);
			goto out;
		}
		sha256d(merkle_tree[1 + i], tx, tx_size);
		if (!submit_coinbase)
			strcat(work->txs, tx_hex);
	}
	n = 1 + tx_count;
	while (n > 1) {
		if (n % 2) {
			memcpy(merkle_tree[n], merkle_tree[n-1], 32);
			++n;
		}
		n /= 2;
		for (i = 0; i < n; i++)
			sha256d(merkle_tree[i], merkle_tree[2*i], 64);
	}

	/* assemble block header */
	work->data[0] = swab32(version);
	for (i = 0; i < 8; i++)
		work->data[8 - i] = le32dec(prevhash + i);
	for (i = 0; i < 8; i++)
		work->data[9 + i] = be32dec((uint32_t *)merkle_tree[0] + i);
	work->data[17] = swab32(curtime);
	work->data[18] = le32dec(&bits);
	memset(work->data + 19, 0x00, 52);
	work->data[20] = 0x80000000;
	work->data[31] = 0x00000280;

	if (unlikely(!jobj_binary(val, "target", target, sizeof(target)))) {
		applog(LOG_ERR, "JSON invalid target");
		goto out;
	}
	for (i = 0; i < ARRAY_SIZE(work->target); i++)
		work->target[7 - i] = be32dec(target + i);

	tmp = json_object_get(val, "workid");
	if (tmp) {
		if (!json_is_string(tmp)) {
			applog(LOG_ERR, "JSON invalid workid");
			goto out;
		}
		work->workid = strdup(json_string_value(tmp));
	}

	rc = true;
out:
	/* Long polling */
	tmp = json_object_get(val, "longpollid");
	if (want_longpoll && json_is_string(tmp)) {
		free(lp_id);
		lp_id = strdup(json_string_value(tmp));
		if (!have_longpoll) {
			char *lp_uri;
			tmp = json_object_get(val, "longpolluri");
			lp_uri = json_is_string(tmp) ? strdup(json_string_value(tmp)) : rpc_url;
			have_longpoll = true;
			tq_push(thr_info[longpoll_thr_id].q, lp_uri);
		}
	}

	free(merkle_tree);
	free(cbtx);
	return rc;
}

static int share_result(int result, struct work *work, const char *reason)
{
	char s[345];
	const char *sres;
	double hashrate;
	int i;

	hashrate = 0.;
	pthread_mutex_lock(&stats_lock);
	for (i = 0; i < g_miner_count; i++)
		hashrate += thr_hashrates[i];
	result ? accepted_count++ : rejected_count++;
	pthread_mutex_unlock(&stats_lock);

	global_hashrate = (uint64_t) hashrate;

	if (use_colors)
		sres = (result ? CL_GRN "yes!" : CL_RED "nooooo");
	else
		sres = (result ? "(yes!!!)" : "(nooooo)");

	sprintf(s, "%.2f", hashrate / 1000000.0);
	applog(LOG_NOTICE, "accepted: %lu/%lu (%.2f%%), %s MH/s %s",
		accepted_count, accepted_count + rejected_count,
		100. * accepted_count / (accepted_count + rejected_count), s, sres);

	if (reason) {
		applog(LOG_WARNING, "reject reason: %s", reason);
		if (strncmp(reason, "low difficulty share", 20) == 0) {
			opt_diff_factor = (opt_diff_factor * 2.0) / 3.0;
			applog(LOG_WARNING, "factor reduced to : %0.2f", opt_diff_factor);
			return 0;
		}
	}
	return 1;
}

static bool submit_upstream_work(CURL *curl, struct work *work)
{
	json_t *val, *res, *reason;
	char s[JSON_BUF_LEN];
	int i;
	bool rc = false;

	/* pass if the previous hash is not the current previous hash */
	if (!submit_old && memcmp(&work->data[1], &g_work.data[1], 32)) {
		if (opt_debug)
			applog(LOG_DEBUG, "DEBUG: stale work detected, discarding");
		return true;
	}

	if (!have_stratum && allow_mininginfo) {
		struct work wheight;
		get_mininginfo(curl, &wheight);
		if (work->height && work->height <= net_blocks) {
			if (opt_debug)
				applog(LOG_WARNING, "block %u was already solved", work->height);
			return true;
		}
	}

	if (have_stratum) {
		uint32_t ntime, nonce;
		char ntimestr[9], noncestr[9];

		if (jsonrpc_2) {
			uchar hash[32];

			bin2hex(noncestr, (const unsigned char *)work->data + 39, 4);
			char *hashhex = abin2hex(hash, 32);
			snprintf(s, JSON_BUF_LEN,
					"{\"method\": \"submit\", \"params\": {\"id\": \"%s\", \"job_id\": \"%s\", \"nonce\": \"%s\", \"result\": \"%s\"}, \"id\":4}\r\n",
					rpc2_id, work->job_id, noncestr, hashhex);
			free(hashhex);
		} else {
			char *xnonce2str;

			le32enc(&ntime, work->data[17]);
			le32enc(&nonce, work->data[19]);

			bin2hex(ntimestr, (const unsigned char *)(&ntime), 4);
			bin2hex(noncestr, (const unsigned char *)(&nonce), 4);
			xnonce2str = abin2hex(work->xnonce2, work->xnonce2_len);
			snprintf(s, JSON_BUF_LEN,
					"{\"method\": \"mining.submit\", \"params\": [\"%s\", \"%s\", \"%s\", \"%s\", \"%s\"], \"id\":4}",
					rpc_user, work->job_id, xnonce2str, ntimestr, noncestr);
			free(xnonce2str);
		}

		if (unlikely(!stratum_send_line(&stratum, s))) {
			applog(LOG_ERR, "submit_upstream_work stratum_send_line failed");
			goto out;
		}

	} else if (work->txs) {

		char data_str[2 * sizeof(work->data) + 1];
		char *req;

		for (i = 0; i < ARRAY_SIZE(work->data); i++)
			be32enc(work->data + i, work->data[i]);
		bin2hex(data_str, (unsigned char *)work->data, 80);
		if (work->workid) {
			char *params;
			val = json_object();
			json_object_set_new(val, "workid", json_string(work->workid));
			params = json_dumps(val, 0);
			json_decref(val);
			req = (char*) malloc(128 + 2 * 80 + strlen(work->txs) + strlen(params));
			sprintf(req,
				"{\"method\": \"submitblock\", \"params\": [\"%s%s\", %s], \"id\":4}\r\n",
				data_str, work->txs, params);
			free(params);
		} else {
			req = (char*) malloc(128 + 2 * 80 + strlen(work->txs));
			sprintf(req,
				"{\"method\": \"submitblock\", \"params\": [\"%s%s\"], \"id\":4}\r\n",
				data_str, work->txs);
		}

		val = json_rpc_call(curl, rpc_url, rpc_userpass, req, NULL, 0);
		free(req);
		if (unlikely(!val)) {
			applog(LOG_ERR, "submit_upstream_work json_rpc_call failed");
			goto out;
		}

		res = json_object_get(val, "result");
		if (json_is_object(res)) {
			char *res_str;
			bool sumres = false;
			void *iter = json_object_iter(res);
			while (iter) {
				if (json_is_null(json_object_iter_value(iter))) {
					sumres = true;
					break;
				}
				iter = json_object_iter_next(res, iter);
			}
			res_str = json_dumps(res, 0);
			share_result(sumres, work, res_str);
			free(res_str);
		} else
			share_result(json_is_null(res), work, json_string_value(res));

		json_decref(val);

	} else {

		char* gw_str = NULL;
		int data_size = 128;
		int adata_sz;

		if (jsonrpc_2) {
			char noncestr[9];
			uchar hash[32];
			char *hashhex;

			bin2hex(noncestr, (const unsigned char *)work->data + 39, 4);
			hashhex = abin2hex(&hash[0], 32);
			snprintf(s, JSON_BUF_LEN,
					"{\"method\": \"submit\", \"params\": "
						"{\"id\": \"%s\", \"job_id\": \"%s\", \"nonce\": \"%s\", \"result\": \"%s\"},"
					"\"id\":4}\r\n",
					rpc2_id, work->job_id, noncestr, hashhex);
			free(hashhex);

			/* issue JSON-RPC request */
			val = json_rpc2_call(curl, rpc_url, rpc_userpass, s, NULL, 0);
			if (unlikely(!val)) {
				applog(LOG_ERR, "submit_upstream_work json_rpc_call failed");
				goto out;
			}
			res = json_object_get(val, "result");
			json_t *status = json_object_get(res, "status");
			bool valid = !strcmp(status ? json_string_value(status) : "", "OK");
			if (valid)
				share_result(valid, work, NULL);
			else {
				json_t *err = json_object_get(res, "error");
				const char *sreason = json_string_value(json_object_get(err, "message"));
				share_result(valid, work, sreason);
				if (!strcasecmp("Invalid job id", sreason)) {
					work_free(work);
					work_copy(work, &g_work);
					g_work_time = 0;
					restart_threads();
				}
			}
			json_decref(val);
			return true;

		}
		
		adata_sz = data_size / sizeof(uint32_t);

		/* build hex string */
		for (i = 0; i < adata_sz; i++)
			le32enc(&work->data[i], work->data[i]);

		gw_str = abin2hex((uchar*)work->data, data_size);

		if (unlikely(!gw_str)) {
			applog(LOG_ERR, "submit_upstream_work OOM");
			return false;
		}

		/* build JSON-RPC request */
		snprintf(s, JSON_BUF_LEN,
			"{\"method\": \"getwork\", \"params\": [\"%s\"], \"id\":4}\r\n", gw_str);
		free(gw_str);

		/* issue JSON-RPC request */
		val = json_rpc_call(curl, rpc_url, rpc_userpass, s, NULL, 0);
		if (unlikely(!val)) {
			applog(LOG_ERR, "submit_upstream_work json_rpc_call failed");
			goto out;
		}
		res = json_object_get(val, "result");
		reason = json_object_get(val, "reject-reason");
		share_result(json_is_true(res), work, reason ? json_string_value(reason) : NULL);

		json_decref(val);
	}

	rc = true;

out:
	return rc;
}

static const char *getwork_req =
	"{\"method\": \"getwork\", \"params\": [], \"id\":0}\r\n";

#define GBT_CAPABILITIES "[\"coinbasetxn\", \"coinbasevalue\", \"longpoll\", \"workid\"]"

static const char *gbt_req =
	"{\"method\": \"getblocktemplate\", \"params\": [{\"capabilities\": "
	GBT_CAPABILITIES "}], \"id\":0}\r\n";
static const char *gbt_lp_req =
	"{\"method\": \"getblocktemplate\", \"params\": [{\"capabilities\": "
	GBT_CAPABILITIES ", \"longpollid\": \"%s\"}], \"id\":0}\r\n";

static bool get_upstream_work(CURL *curl, struct work *work)
{
	json_t *val;
	int err;
	bool rc;
	struct timeval tv_start, tv_end, diff;

start:
	gettimeofday(&tv_start, NULL);

	if (jsonrpc_2) {
		char s[128];
		snprintf(s, 128, "{\"method\": \"getjob\", \"params\": {\"id\": \"%s\"}, \"id\":1}\r\n", rpc2_id);
		val = json_rpc2_call(curl, rpc_url, rpc_userpass, s, NULL, 0);
	} else {
		val = json_rpc_call(curl, rpc_url, rpc_userpass,
		                    have_gbt ? gbt_req : getwork_req,
		                    &err, have_gbt ? JSON_RPC_QUIET_404 : 0);
	}
	gettimeofday(&tv_end, NULL);

	if (have_stratum) {
		if (val)
			json_decref(val);
		return true;
	}

	if (!have_gbt && !allow_getwork) {
		applog(LOG_ERR, "No usable protocol");
		if (val)
			json_decref(val);
		return false;
	}

	if (have_gbt && allow_getwork && !val && err == CURLE_OK) {
		applog(LOG_NOTICE, "getblocktemplate failed, falling back to getwork");
		have_gbt = false;
		goto start;
	}

	if (!val)
		return false;

	if (have_gbt) {
		rc = gbt_work_decode(json_object_get(val, "result"), work);
		if (!have_gbt) {
			json_decref(val);
			goto start;
		}
	} else {
		rc = work_decode(json_object_get(val, "result"), work);
	}

	if (opt_protocol && rc) {
		timeval_subtract(&diff, &tv_end, &tv_start);
		applog(LOG_DEBUG, "got new work in %.2f ms",
		       (1000.0 * diff.tv_sec) + (0.001 * diff.tv_usec));
	}

	json_decref(val);

	// store work height in solo
	get_mininginfo(curl, work);

	return rc;
}

static void workio_cmd_free(struct workio_cmd *wc)
{
	if (!wc)
		return;

	switch (wc->cmd) {
	case WC_SUBMIT_WORK:
		work_free(wc->u.work);
		free(wc->u.work);
		break;
	default: /* do nothing */
		break;
	}

	memset(wc, 0, sizeof(*wc)); /* poison */
	free(wc);
}

static bool workio_get_work(struct workio_cmd *wc, CURL *curl)
{
	struct work *ret_work;
	int failures = 0;

	ret_work = (struct work*) calloc(1, sizeof(*ret_work));
	if (!ret_work)
		return false;

	/* obtain new work from bitcoin via JSON-RPC */
	while (!get_upstream_work(curl, ret_work)) {
		if (unlikely((opt_retries >= 0) && (++failures > opt_retries))) {
			applog(LOG_ERR, "json_rpc_call failed, terminating workio thread");
			free(ret_work);
			return false;
		}

		/* pause, then restart work-request loop */
		applog(LOG_ERR, "json_rpc_call failed, retry after %d seconds",
			opt_fail_pause);
		sleep(opt_fail_pause);
	}

	/* send work to requesting thread */
	if (!tq_push(wc->thr->q, ret_work))
		free(ret_work);

	return true;
}

static bool workio_submit_work(struct workio_cmd *wc, CURL *curl)
{
	int failures = 0;

	/* submit solution via JSON-RPC */
	while (!submit_upstream_work(curl, wc->u.work)) {
		if (unlikely((opt_retries >= 0) && (++failures > opt_retries))) {
			applog(LOG_ERR, "...terminating workio thread");
			return false;
		}

		/* pause, then restart work-request loop */
		applog(LOG_ERR, "...retry after %d seconds", opt_fail_pause);
		sleep(opt_fail_pause);
	}

	return true;
}

bool rpc2_login(CURL *curl)
{
	json_t *val;
	bool rc = false;
	struct timeval tv_start, tv_end, diff;
	char s[JSON_BUF_LEN];

	if (!jsonrpc_2)
		return false;

	snprintf(s, JSON_BUF_LEN, "{\"method\": \"login\", \"params\": {"
		"\"login\": \"%s\", \"pass\": \"%s\", \"agent\": \"%s\"}, \"id\": 1}",
		rpc_user, rpc_pass, USER_AGENT);

	gettimeofday(&tv_start, NULL);
	val = json_rpc_call(curl, rpc_url, rpc_userpass, s, NULL, 0);
	gettimeofday(&tv_end, NULL);

	if (!val)
		goto end;

//	applog(LOG_DEBUG, "JSON value: %s", json_dumps(val, 0));

	rc = rpc2_login_decode(val);

	json_t *result = json_object_get(val, "result");

	if (!result)
		goto end;

	json_t *job = json_object_get(result, "job");
	if (!rpc2_job_decode(job, &g_work)) {
		goto end;
	}

	if (opt_debug && rc) {
		timeval_subtract(&diff, &tv_end, &tv_start);
		applog(LOG_DEBUG, "DEBUG: authenticated in %d ms",
				diff.tv_sec * 1000 + diff.tv_usec / 1000);
	}

	json_decref(val);
end:
	return rc;
}

bool rpc2_workio_login(CURL *curl)
{
	int failures = 0;

	/* submit solution to bitcoin via JSON-RPC */
	pthread_mutex_lock(&rpc2_login_lock);
	while (!rpc2_login(curl)) {
		if (unlikely((opt_retries >= 0) && (++failures > opt_retries))) {
			applog(LOG_ERR, "...terminating workio thread");
			pthread_mutex_unlock(&rpc2_login_lock);
			return false;
		}

		/* pause, then restart work-request loop */
		applog(LOG_ERR, "...retry after %d seconds", opt_fail_pause);
		sleep(opt_fail_pause);
		pthread_mutex_unlock(&rpc2_login_lock);
		pthread_mutex_lock(&rpc2_login_lock);
	}
	pthread_mutex_unlock(&rpc2_login_lock);

	return true;
}

static void *workio_thread(void *userdata)
{
	struct thr_info *mythr = (struct thr_info *) userdata;
	CURL *curl;
	bool ok = true;

	curl = curl_easy_init();
	if (unlikely(!curl)) {
		applog(LOG_ERR, "CURL initialization failed");
		return NULL;
	}

	if(jsonrpc_2 && !have_stratum) {
		ok = rpc2_workio_login(curl);
	}

	while (ok) {
		struct workio_cmd *wc;

		/* wait for workio_cmd sent to us, on our queue */
		wc = (struct workio_cmd *) tq_pop(mythr->q, NULL);
		if (!wc) {
			ok = false;
			break;
		}

		/* process workio_cmd */
		switch (wc->cmd) {
		case WC_GET_WORK:
			ok = workio_get_work(wc, curl);
			break;
		case WC_SUBMIT_WORK:
			ok = workio_submit_work(wc, curl);
			break;

		default:		/* should never happen */
			ok = false;
			break;
		}

		workio_cmd_free(wc);
	}

	tq_freeze(mythr->q);
	curl_easy_cleanup(curl);

	return NULL;
}

static bool get_work(struct thr_info *thr, struct work *work)
{
	struct workio_cmd *wc;
	struct work *work_heap;

	/* fill out work request message */
	wc = (struct workio_cmd *) calloc(1, sizeof(*wc));
	if (!wc)
		return false;

	wc->cmd = WC_GET_WORK;
	wc->thr = thr;

	/* send work request to workio thread */
	if (!tq_push(thr_info[work_thr_id].q, wc)) {
		workio_cmd_free(wc);
		return false;
	}

	/* wait for response, a unit of work */
	work_heap = (struct work*) tq_pop(thr->q, NULL);
	if (!work_heap)
		return false;

	/* copy returned work into storage provided by caller */
	memcpy(work, work_heap, sizeof(*work));
	free(work_heap);

	return true;
}

static bool submit_work(struct thr_info *thr, const struct work *work_in)
{
	struct workio_cmd *wc;

	/* fill out work request message */
	wc = (struct workio_cmd *) calloc(1, sizeof(*wc));
	if (!wc)
		return false;

	wc->u.work = (struct work*) malloc(sizeof(*work_in));
	if (!wc->u.work)
		goto err_out;

	wc->cmd = WC_SUBMIT_WORK;
	wc->thr = thr;
	work_copy(wc->u.work, work_in);

	/* send solution to workio thread */
	if (!tq_push(thr_info[work_thr_id].q, wc))
		goto err_out;

	return true;

err_out:
	workio_cmd_free(wc);
	return false;
}

static void stratum_gen_work(struct stratum_ctx *sctx, struct work *work)
{
	unsigned char merkle_root[64];
	int i, t;

	pthread_mutex_lock(&sctx->work_lock);

	if (jsonrpc_2) {
		work_free(work);
		work_copy(work, &sctx->work);
		pthread_mutex_unlock(&sctx->work_lock);
	} else {
		free(work->job_id);
		work->job_id = strdup(sctx->job.job_id);
		work->xnonce2_len = sctx->xnonce2_size;
		work->xnonce2 = (uchar*) realloc(work->xnonce2, sctx->xnonce2_size);
		memcpy(work->xnonce2, sctx->job.xnonce2, sctx->xnonce2_size);

		/* Generate merkle root */
		if (!sctx->job.coinbase_hash_mode)
			switch (opt_algo) {
				case ALGO_GROESTL:
				case ALGO_BLAKECOIN:
						sctx->job.coinbase_hash_mode = 1;
						break;
					default:
						sctx->job.coinbase_hash_mode = 2;
						break;
				}
		switch (sctx->job.coinbase_hash_mode) {
			case 1:
				SHA256(sctx->job.coinbase, (int) sctx->job.coinbase_size, merkle_root);
				break;
			case 2:
				sha256d(merkle_root, sctx->job.coinbase, (int) sctx->job.coinbase_size);
				break;
		}

		for (i = 0; i < sctx->job.merkle_count; i++) {
			memcpy(merkle_root + 32, sctx->job.merkle[i], 32);
			sha256d(merkle_root, merkle_root, 64);
		}

		/* Increment extranonce2 */
		for (t = 0; t < sctx->xnonce2_size && !(++sctx->job.xnonce2[t]); t++)
			;

		/* Assemble block header */
		memset(work->data, 0, 128);
		work->data[0] = le32dec(sctx->job.version);
		for (i = 0; i < 8; i++)
			work->data[1 + i] = le32dec((uint32_t *) sctx->job.prevhash + i);
		for (i = 0; i < 8; i++)
			work->data[9 + i] = be32dec((uint32_t *) merkle_root + i);
		work->data[17] = le32dec(sctx->job.ntime);
		work->data[18] = le32dec(sctx->job.nbits);
		work->data[20] = 0x80000000;
		work->data[31] = 0x00000280;

		switch (opt_algo) {
			case ALGO_DMD_GR:
			case ALGO_GROESTL:
				diff_to_target(work->target, sctx->job.diff / (256.0 * opt_diff_factor));
				break;
			default:
				diff_to_target(work->target, sctx->job.diff / opt_diff_factor);
		}

		pthread_mutex_unlock(&sctx->work_lock);

		g_net_diff = ConvertBitsToDouble(swab32(le32dec(sctx->job.nbits)));
		diff_to_target(work->block_target, g_net_diff);

		if (opt_debug) {
			char *xnonce2str = abin2hex(work->xnonce2, work->xnonce2_len);
			applog(LOG_DEBUG, "DEBUG: job_id='%s' extranonce2=%s ntime=%08x",
					work->job_id, xnonce2str, swab32(work->data[17]));
			free(xnonce2str);
		}
	}
}

bool rpc2_stratum_job(struct stratum_ctx *sctx, json_t *params)
{
	bool ret = false;
	pthread_mutex_lock(&sctx->work_lock);
	ret = rpc2_job_decode(params, &sctx->work);

	if (ret) {
		work_free(&g_work);
		work_copy(&g_work, &sctx->work);
		g_work_time = 0;
	}

	pthread_mutex_unlock(&sctx->work_lock);

	return ret;
}

static void *miner_thread(void *userdata)
{
	struct thr_info *mythr = (struct thr_info *) userdata;
	int thr_id = mythr->id;
	struct work work;
	uint32_t max_nonce;
	uint32_t end_nonce = 0xffffffffU / opt_n_threads * (thr_id + 1) - 0x20;
	time_t firstwork_time = 0;
	unsigned char *scratchbuf = NULL;
	char s[16];
	int i;

	memset(&work, 0, sizeof(work));

	/* Set worker threads to nice 19 and then preferentially to SCHED_IDLE
	 * and if that fails, then SCHED_BATCH. No need for this to be an
	 * error if it fails */
	if (opt_priority == 0) {
		setpriority(PRIO_PROCESS, 0, 19);
		drop_policy();
	} else {
		int prio = 0;
#ifndef WIN32
		prio = 18;
		// note: different behavior on linux (-19 to 19)
		switch (opt_priority) {
			case 1:
				prio = 5;
				break;
			case 2:
				prio = 0;
				break;
			case 3:
				prio = -5;
				break;
			case 4:
				prio = -10;
				break;
			case 5:
				prio = -15;
		}
		if (opt_debug)
			applog(LOG_DEBUG, "Thread %d priority %d (nice %d)",
				thr_id,	opt_priority, prio);
#endif
		setpriority(PRIO_PROCESS, 0, prio);
		if (opt_priority == 0) {
			drop_policy();
		}
	}

	/* Cpu thread affinity */
	if (num_cpus > 1) {
		if (opt_affinity == -1 && opt_n_threads > 1) {
			if (opt_debug)
				applog(LOG_DEBUG, "Binding thread %d to cpu %d (mask %x)", thr_id,
						thr_id % num_cpus, (1 << (thr_id % num_cpus)));
			affine_to_cpu_mask(thr_id, 1 << (thr_id % num_cpus));
		} else if (opt_affinity != -1) {
			if (opt_debug)
				applog(LOG_DEBUG, "Binding thread %d to cpu mask %x", thr_id,
						opt_affinity);
			affine_to_cpu_mask(thr_id, opt_affinity);
		}
	}

	while (1) {
		uint64_t hashes_done;
		struct timeval tv_start, tv_end, diff;
		int64_t max64;
		int wkcmp_offset = 0;
		int nonce_oft = 19*sizeof(uint32_t); // 76
		int wkcmp_sz = nonce_oft;
		int rc = 0;

		if (jsonrpc_2) {
			wkcmp_sz = nonce_oft = 39;
		}

		uint32_t *nonceptr = (uint32_t*) (((char*)work.data) + nonce_oft);

		if (have_stratum) {
			while (!jsonrpc_2 && time(NULL) >= g_work_time + 120)
				sleep(1);

			pthread_mutex_lock(&g_work_lock);

			if ( (*nonceptr) >= end_nonce
				&& !( memcmp(&work.data[wkcmp_offset], &g_work.data[wkcmp_offset], wkcmp_sz) ||
				 jsonrpc_2 ? memcmp(((uint8_t*) work.data) + 43, ((uint8_t*) g_work.data) + 43, 33) : 0))
			{
				stratum_gen_work(&stratum, &g_work);
			}

		} else {

			int min_scantime = have_longpoll ? LP_SCANTIME : opt_scantime;
			/* obtain new work from internal workio thread */
			pthread_mutex_lock(&g_work_lock);
			if (!have_stratum &&
			    (time(NULL) - g_work_time >= min_scantime ||
			     work.data[19] >= end_nonce)) {
				if (unlikely(!get_work(mythr, &g_work))) {
					applog(LOG_ERR, "work retrieval failed, exiting "
						"mining thread %d", mythr->id);
					pthread_mutex_unlock(&g_work_lock);
					goto out;
				}
				g_work_time = have_stratum ? 0 : time(NULL);
			}
			if (have_stratum) {
				pthread_mutex_unlock(&g_work_lock);
				continue;
			}
		}
		if (memcmp(&work.data[wkcmp_offset], &g_work.data[wkcmp_offset], wkcmp_sz) ||
			jsonrpc_2 ? memcmp(((uint8_t*) work.data) + 43, ((uint8_t*) g_work.data) + 43, 33) : 0)
		{
			work_free(&work);
			work_copy(&work, &g_work);
			nonceptr = (uint32_t*) (((char*)work.data) + nonce_oft);
			*nonceptr = 0xffffffffU / opt_n_threads * thr_id;
		} else
			++(*nonceptr);
		pthread_mutex_unlock(&g_work_lock);
		work_restart[thr_id].restart = 0;

		/* prevent scans before a job is received */
		if (have_stratum && !work.data[0]) {
			sleep(1);
			continue;
		}

		/* adjust max_nonce to meet target scan time */
		if (have_stratum)
			max64 = LP_SCANTIME;
		else
			max64 = g_work_time + (have_longpoll ? LP_SCANTIME : opt_scantime)
					- time(NULL);

		max64 *= (int64_t) thr_hashrates[thr_id];

		if (max64 <= 0) {
			switch (opt_algo) {
			case ALGO_DMD_GR:
			case ALGO_GROESTL:
			case ALGO_MYR_GR:
				max64 = 0x3ffff;
				break;
			case ALGO_BLAKE2S:
			case ALGO_BLAKECOIN:
			case ALGO_VCASH:
				max64 = 0x7ffffLL;
				break;
			default:
				max64 = 0x1fffffLL;
				break;
			}
		}
		if ((*nonceptr) + max64 > end_nonce)
			max_nonce = end_nonce;
		else
			max_nonce = (*nonceptr) + (uint32_t) max64;

		hashes_done = 0;
		gettimeofday((struct timeval *) &tv_start, NULL);

		if (firstwork_time == 0)
			firstwork_time = time(NULL);

		/* scan nonces for a proof-of-work hash */
		switch (opt_algo) {
		case ALGO_BLAKE2S:
			rc = scanhash_blake2s(thr_id, work.data, work.target, max_nonce, &hashes_done);
			break;
		case ALGO_DMD_GR:
		case ALGO_GROESTL:
			rc = scanhash_groestl(thr_id, work.data, work.target, max_nonce, &hashes_done);
			break;
		case ALGO_MYR_GR:
			rc = scanhash_myriad(thr_id, work.data, work.target, max_nonce, &hashes_done);
			break;
		case ALGO_BLAKECOIN:
		case ALGO_VCASH:
			rc = scanhash_blake256_8(thr_id, work.data, work.target, max_nonce, &hashes_done);
			break;
		case ALGO_KECCAK256:
			rc = scanhash_keccak256(thr_id, work.data, work.target, max_nonce, &hashes_done);
			break;
		case ALGO_KECCAK512:
			rc = scanhash_keccak512(thr_id, work.data, work.target, max_nonce, &hashes_done);
			break;
		case ALGO_LYRA2REV2:
			rc = scanhash_lyra2rev2(thr_id, work.data, work.target, max_nonce, &hashes_done);
			break;
		case ALGO_LYRA2Z:
			rc = scanhash_lyra2z(thr_id, work.data, work.target, max_nonce, &hashes_done);
			break;
		case ALGO_NIST5:
			rc = scanhash_nist5(thr_id, work.data, work.target, max_nonce, &hashes_done);
			break;
		default:
			/* should never happen */
			goto out;
		}

		/* record scanhash elapsed time */
		gettimeofday(&tv_end, NULL);
		timeval_subtract(&diff, &tv_end, &tv_start);
		if (diff.tv_usec || diff.tv_sec) {
			pthread_mutex_lock(&stats_lock);
			thr_hashrates[thr_id] =
				hashes_done / (diff.tv_sec + diff.tv_usec * 1e-6);
			pthread_mutex_unlock(&stats_lock);
		}
		if (!opt_quiet) {
			sprintf(s, thr_hashrates[thr_id] >= 1e6 ? "%.0f" : "%.2f",
					thr_hashrates[thr_id] / 1e3);
			applog(LOG_INFO, "CPU #%d: %s kH/s", thr_id, s);
		}

		/* if nonce found, submit work */
		if (rc) {
			if (!submit_work(mythr, &work))
				break;
			// prevent stale work in solo
			// we can't submit twice a block!
			if (!have_stratum && !have_longpoll) {
				pthread_mutex_lock(&g_work_lock);
				// will force getwork
				g_work_time = 0;
				pthread_mutex_unlock(&g_work_lock);
				continue;
			}
		}

	}

out:
	tq_freeze(mythr->q);

	return NULL;
}

void restart_threads(void)
{
	int i;

//	for (i = 0; i < opt_n_threads; i++)
	for (i = 0; i < g_miner_count; i++)
		work_restart[i].restart = 1;
}

static void *longpoll_thread(void *userdata)
{
	struct thr_info *mythr = (struct thr_info*) userdata;
	CURL *curl = NULL;
	char *copy_start, *hdr_path = NULL, *lp_url = NULL;
	bool need_slash = false;

	curl = curl_easy_init();
	if (unlikely(!curl)) {
		applog(LOG_ERR, "CURL init failed");
		goto out;
	}

start:
	hdr_path = (char*) tq_pop(mythr->q, NULL);
	if (!hdr_path)
		goto out;

	/* full URL */
	if (strstr(hdr_path, "://")) {
		lp_url = hdr_path;
		hdr_path = NULL;
	}

	/* absolute path, on current server */
	else {
		copy_start = (*hdr_path == '/') ? (hdr_path + 1) : hdr_path;
		if (rpc_url[strlen(rpc_url) - 1] != '/')
			need_slash = true;

		lp_url = (char*) malloc(strlen(rpc_url) + strlen(copy_start) + 2);
		if (!lp_url)
			goto out;

		sprintf(lp_url, "%s%s%s", rpc_url, need_slash ? "/" : "", copy_start);
	}

	if (!opt_quiet)
		applog(LOG_INFO, "Longpoll enabled for %s", lp_url);

	while (1) {
		json_t *val;
		char *req = NULL;
		int err;

		if (jsonrpc_2) {
			char s[128];
			pthread_mutex_lock(&rpc2_login_lock);
			if (!strlen(rpc2_id)) {
				sleep(1);
				continue;
			}
			snprintf(s, 128, "{\"method\": \"getjob\", \"params\": {\"id\": \"%s\"}, \"id\":1}\r\n", rpc2_id);
			pthread_mutex_unlock(&rpc2_login_lock);
			val = json_rpc2_call(curl, rpc_url, rpc_userpass, s, &err, JSON_RPC_LONGPOLL);
		} else {
			if (have_gbt) {
				req = (char*) malloc(strlen(gbt_lp_req) + strlen(lp_id) + 1);
				sprintf(req, gbt_lp_req, lp_id);
			}
			val = json_rpc_call(curl, rpc_url, rpc_userpass, getwork_req, &err, JSON_RPC_LONGPOLL);
			val = json_rpc_call(curl, lp_url, rpc_userpass,
					    req ? req : getwork_req, &err,
					    JSON_RPC_LONGPOLL);
			free(req);
		}

		if (have_stratum) {
			if (val)
				json_decref(val);
			goto out;
		}
		if (likely(val)) {
			bool rc;
			char *start_job_id;
			json_t *res, *soval;
			res = json_object_get(val, "result");
			if (!jsonrpc_2) {
				soval = json_object_get(res, "submitold");
				submit_old = soval ? json_is_true(soval) : false;
			}
			pthread_mutex_lock(&g_work_lock);
			start_job_id = g_work.job_id ? strdup(g_work.job_id) : NULL;
			if (have_gbt)
				rc = gbt_work_decode(res, &g_work);
			else
				rc = work_decode(res, &g_work);
			if (rc) {
				if (g_work.job_id && strcmp(start_job_id, g_work.job_id)) {
					if (opt_debug)
						applog(LOG_BLUE, "Longpoll pushed new work");
					time(&g_work_time);
					restart_threads();
				}
			}
			free(start_job_id);
			pthread_mutex_unlock(&g_work_lock);
			json_decref(val);
		} else {
			pthread_mutex_lock(&g_work_lock);
			g_work_time -= LP_SCANTIME;
			pthread_mutex_unlock(&g_work_lock);
			if (err == CURLE_OPERATION_TIMEDOUT) {
				restart_threads();
			} else {
				have_longpoll = false;
				restart_threads();
				free(hdr_path);
				free(lp_url);
				lp_url = NULL;
				sleep(opt_fail_pause);
				goto start;
			}
		}
	}

out:
	free(hdr_path);
	free(lp_url);
	tq_freeze(mythr->q);
	if (curl)
		curl_easy_cleanup(curl);

	return NULL;
}

static bool stratum_handle_response(char *buf)
{
	json_t *val, *err_val, *res_val, *id_val;
	json_error_t err;
	bool ret = false;
	bool valid = false;

	val = JSON_LOADS(buf, &err);
	if (!val) {
		applog(LOG_INFO, "JSON decode failed(%d): %s", err.line, err.text);
		goto out;
	}

	res_val = json_object_get(val, "result");
	err_val = json_object_get(val, "error");
	id_val = json_object_get(val, "id");

	if (!id_val || json_is_null(id_val))
		goto out;

	if (jsonrpc_2)
	{
		if (!res_val && !err_val)
			goto out;

		json_t *status = json_object_get(res_val, "status");
		if(status) {
			const char *s = json_string_value(status);
			valid = !strcmp(s, "OK") && json_is_null(err_val);
		} else {
			valid = json_is_null(err_val);
		}
		share_result(valid, NULL, err_val ? json_string_value(err_val) : NULL);

	} else {

		if (!res_val || json_integer_value(id_val) < 4)
			goto out;
		valid = json_is_true(res_val);
		share_result(valid, NULL, err_val ? json_string_value(json_array_get(err_val, 1)) : NULL);
	}

	ret = true;

out:
	if (val)
		json_decref(val);

	return ret;
}

static void *stratum_thread(void *userdata)
{
	struct thr_info *mythr = (struct thr_info *) userdata;
	char *s;

	stratum.url = (char*) tq_pop(mythr->q, NULL);
	if (!stratum.url)
		goto out;
	applog(LOG_INFO, "Starting Stratum on %s", stratum.url);

	while (1) {
		int failures = 0;

		if (stratum_need_reset) {
			stratum_need_reset = false;
			stratum_disconnect(&stratum);
			if (strcmp(stratum.url, rpc_url)) {
				free(stratum.url);
				stratum.url = strdup(rpc_url);
				applog(LOG_BLUE, "Connection changed to %s", short_url);
			} else if (!opt_quiet) {
				applog(LOG_DEBUG, "Stratum connection reset");
			}
		}

		while (!stratum.curl) {
			pthread_mutex_lock(&g_work_lock);
			g_work_time = 0;
			pthread_mutex_unlock(&g_work_lock);
			restart_threads();

			if (!stratum_connect(&stratum, stratum.url)
					|| !stratum_subscribe(&stratum)
					|| !stratum_authorize(&stratum, rpc_user, rpc_pass)) {
				stratum_disconnect(&stratum);
				if (opt_retries >= 0 && ++failures > opt_retries) {
					applog(LOG_ERR, "...terminating workio thread");
					tq_push(thr_info[work_thr_id].q, NULL);
					goto out;
				}
				applog(LOG_ERR, "...retry after %d seconds", opt_fail_pause);
				sleep(opt_fail_pause);
			}

			if (jsonrpc_2) {
				work_free(&g_work);
				work_copy(&g_work, &stratum.work);
			}
		}

		if (stratum.job.job_id &&
			(!g_work_time || strcmp(stratum.job.job_id, g_work.job_id)) )
		{
			pthread_mutex_lock(&g_work_lock);
			stratum_gen_work(&stratum, &g_work);
			time(&g_work_time);
			pthread_mutex_unlock(&g_work_lock);

			if (stratum.job.clean || jsonrpc_2) {
				if (!opt_quiet)
					applog(LOG_BLUE, "%s %s block %d", short_url, algo_names[opt_algo],
						stratum.bloc_height);
				restart_threads();
			} else if (opt_debug && !opt_quiet) {
					applog(LOG_BLUE, "%s asks job %d for block %d", short_url,
						strtoul(stratum.job.job_id, NULL, 16), stratum.bloc_height);
			}
		}

		if (!stratum_socket_full(&stratum, opt_timeout)) {
			applog(LOG_ERR, "Stratum connection timeout");
			s = NULL;
		} else
			s = stratum_recv_line(&stratum);
		if (!s) {
			stratum_disconnect(&stratum);
			applog(LOG_ERR, "Stratum connection interrupted");
			continue;
		}
		if (!stratum_handle_method(&stratum, s))
			stratum_handle_response(s);
		free(s);
	}
out:
	return NULL;
}

static void show_version_and_exit(void)
{
	printf("\n built on " __DATE__
#ifdef _MSC_VER
	 " with VC++ 2013\n");
#elif defined(__GNUC__)
	 " with GCC");
	printf(" %d.%d.%d\n", __GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__);
#endif

	printf(" features:"
#if defined(USE_ASM) && defined(__i386__)
		" i386"
#endif
#if defined(USE_ASM) && defined(__x86_64__)
		" x86_64"
#endif
#if defined(USE_ASM) && (defined(__i386__) || defined(__x86_64__))
		" SSE2"
#endif
#if defined(__x86_64__) && defined(USE_AVX)
		" AVX"
#endif
#if defined(__x86_64__) && defined(USE_AVX2)
		" AVX2"
#endif
#if defined(__x86_64__) && defined(USE_XOP)
		" XOP"
#endif
#if defined(USE_ASM) && defined(__arm__) && defined(__APCS_32__)
		" ARM"
#if defined(__ARM_ARCH_5E__) || defined(__ARM_ARCH_5TE__) || \
	defined(__ARM_ARCH_5TEJ__) || defined(__ARM_ARCH_6__) || \
	defined(__ARM_ARCH_6J__) || defined(__ARM_ARCH_6K__) || \
	defined(__ARM_ARCH_6M__) || defined(__ARM_ARCH_6T2__) || \
	defined(__ARM_ARCH_6Z__) || defined(__ARM_ARCH_6ZK__) || \
	defined(__ARM_ARCH_7__) || \
	defined(__ARM_ARCH_7A__) || defined(__ARM_ARCH_7R__) || \
	defined(__ARM_ARCH_7M__) || defined(__ARM_ARCH_7EM__)
		" ARMv5E"
#endif
#if defined(__ARM_NEON__)
		" NEON"
#endif
#endif
		"\n\n");

	/* dependencies versions */
	printf("%s\n", curl_version());
#ifdef JANSSON_VERSION
	printf("jansson/%s ", JANSSON_VERSION);
#endif
#ifdef PTW32_VERSION
	printf("pthreads/%d.%d.%d.%d ", PTW32_VERSION);
#endif
	printf("\n");
	exit(0);
}

static void show_usage_and_exit(int status)
{
	if (status)
		fprintf(stderr, "Try `" PACKAGE_NAME " --help' for more information.\n");
	else
		printf(usage);
	exit(status);
}

static void strhide(char *s)
{
	if (*s) *s++ = 'x';
	while (*s) *s++ = '\0';
}

static bool get_serial_fpga_list(char *arg)
{
	char *token = strtok(arg, ", \n\r");
	
	g_serial_device_count = 0;

    while(token != NULL)
    {
		serial_fpga_list[g_serial_device_count] = malloc(strlen(token) + 1);
		strcpy(serial_fpga_list[g_serial_device_count++], token);
        token = strtok(NULL, ", \n\r");
    }
	
	if (g_serial_device_count == 0) {
		fprintf(stderr, "ERROR: Unable to parse --scan-serial parameter\n");
		return false;
	}

	return true;
}

void parse_arg(int key, char *arg)
{
	char *p;
	int v, i;
	double d;

	switch(key) {
	case 'a':
		for (i = 0; i < ALGO_COUNT; i++) {
			v = (int) strlen(algo_names[i]);
			if (!strncmp(arg, algo_names[i], v)) {
				if (arg[v] == '\0') {
					opt_algo = (enum algos) i;
					break;
				}
			}
		}
		if (i == ALGO_COUNT) {
			applog(LOG_ERR, "Unknown algo parameter '%s'", arg);
			show_usage_and_exit(1);
		}
		break;
	case 'b':
		p = strstr(arg, ":");
		if (p) {
			/* ip:port */
			if (p - arg > 0) {
				free(opt_api_allow);
				opt_api_allow = strdup(arg);
				opt_api_allow[p - arg] = '\0';
			}
			opt_api_listen = atoi(p + 1);
		}
		else if (arg && strstr(arg, ".")) {
			/* ip only */
			free(opt_api_allow);
			opt_api_allow = strdup(arg);
		}
		else if (arg) {
			/* port or 0 to disable */
			opt_api_listen = atoi(arg);
		}
		break;
	case 1030: /* --api-remote */
		opt_api_remote = 1;
		break;
	case 'c': {
		json_error_t err;
		json_t *config = JSON_LOAD_FILE(arg, &err);
		if (!json_is_object(config)) {
			if (err.line < 0)
				fprintf(stderr, "%s\n", err.text);
			else
				fprintf(stderr, "%s:%d: %s\n",
					arg, err.line, err.text);
		} else {
			parse_config(config, arg);
			json_decref(config);
		}
		break;
	}
	case 'C':
		opt_use_cpu = true;
		break;
	case 'q':
		opt_quiet = true;
		break;
	case 'D':
		opt_debug = true;
		break;
	case 'p':
		free(rpc_pass);
		rpc_pass = strdup(arg);
		strhide(arg);
		break;
	case 'P':
		opt_protocol = true;
		break;
	case 'r':
		v = atoi(arg);
		if (v < -1 || v > 9999) /* sanity check */
			show_usage_and_exit(1);
		opt_retries = v;
		break;
	case 'R':
		v = atoi(arg);
		if (v < 1 || v > 9999) /* sanity check */
			show_usage_and_exit(1);
		opt_fail_pause = v;
		break;
	case 's':
		v = atoi(arg);
		if (v < 1 || v > 9999) /* sanity check */
			show_usage_and_exit(1);
		opt_scantime = v;
		break;
	case 'S':
		if (!get_serial_fpga_list(arg))
			show_usage_and_exit(1);
		opt_use_serial = true;
		break;
	case 'T':
		v = atoi(arg);
		if (v < 1 || v > 99999) /* sanity check */
			show_usage_and_exit(1);
		opt_timeout = v;
		break;
	case 't':
		v = atoi(arg);
		if (v < 0 || v > 9999) /* sanity check */
			show_usage_and_exit(1);
		opt_n_threads = v;
		break;
	case 'u':
		free(rpc_user);
		rpc_user = strdup(arg);
		break;
	case 'o': {			/* --url */
		char *ap, *hp;
		ap = strstr(arg, "://");
		ap = ap ? ap + 3 : arg;
		hp = strrchr(arg, '@');
		if (hp) {
			*hp = '\0';
			p = strchr(ap, ':');
			if (p) {
				free(rpc_userpass);
				rpc_userpass = strdup(ap);
				free(rpc_user);
				rpc_user = (char*) calloc(p - ap + 1, 1);
				strncpy(rpc_user, ap, p - ap);
				free(rpc_pass);
				rpc_pass = strdup(++p);
				if (*p) *p++ = 'x';
				v = (int) strlen(hp + 1) + 1;
				memmove(p + 1, hp + 1, v);
				memset(p + v, 0, hp - p);
				hp = p;
			} else {
				free(rpc_user);
				rpc_user = strdup(ap);
			}
			*hp++ = '@';
		} else
			hp = ap;
		if (ap != arg) {
			if (strncasecmp(arg, "http://", 7) &&
			    strncasecmp(arg, "https://", 8) &&
			    strncasecmp(arg, "stratum+tcp://", 14)) {
				fprintf(stderr, "unknown protocol -- '%s'\n", arg);
				show_usage_and_exit(1);
			}
			free(rpc_url);
			rpc_url = strdup(arg);
			strcpy(rpc_url + (ap - arg), hp);
			short_url = &rpc_url[ap - arg];
		} else {
			if (*hp == '\0' || *hp == '/') {
				fprintf(stderr, "invalid URL -- '%s'\n",
					arg);
				show_usage_and_exit(1);
			}
			free(rpc_url);
			rpc_url = (char*) malloc(strlen(hp) + 8);
			sprintf(rpc_url, "http://%s", hp);
			short_url = &rpc_url[sizeof("http://")-1];
		}
		have_stratum = !strncasecmp(rpc_url, "stratum", 7);
		break;
	}
	case 'O':			/* --userpass */
		p = strchr(arg, ':');
		if (!p) {
			fprintf(stderr, "invalid username:password pair -- '%s'\n", arg);
			show_usage_and_exit(1);
		}
		free(rpc_userpass);
		rpc_userpass = strdup(arg);
		free(rpc_user);
		rpc_user = (char*) calloc(p - arg + 1, 1);
		strncpy(rpc_user, arg, p - arg);
		free(rpc_pass);
		rpc_pass = strdup(++p);
		strhide(p);
		break;
	case 'x':			/* --proxy */
		if (!strncasecmp(arg, "socks4://", 9))
			opt_proxy_type = CURLPROXY_SOCKS4;
		else if (!strncasecmp(arg, "socks5://", 9))
			opt_proxy_type = CURLPROXY_SOCKS5;
#if LIBCURL_VERSION_NUM >= 0x071200
		else if (!strncasecmp(arg, "socks4a://", 10))
			opt_proxy_type = CURLPROXY_SOCKS4A;
		else if (!strncasecmp(arg, "socks5h://", 10))
			opt_proxy_type = CURLPROXY_SOCKS5_HOSTNAME;
#endif
		else
			opt_proxy_type = CURLPROXY_HTTP;
		free(opt_proxy);
		opt_proxy = strdup(arg);
		break;
	case 'z':
		v = atoi(arg);
		if (v < 25 || v > 250) {
			applog(LOG_ERR, "ZTEX frequency must be between 25 Mhz and 250 Mhz");
			show_usage_and_exit(1);
		}
		opt_use_ztex = true;
		g_ztex_freq = (int)((v/4)-1);
		break;
	case 'F':
		opt_firmware = true;
		break;
	case 1001:
		free(opt_cert);
		opt_cert = strdup(arg);
		break;
	case 1002:
		use_colors = false;
		break;
	case 1003:
		want_longpoll = false;
		break;
	case 1004:
		opt_auto_freq = true;
		break;
	case 1007:
		want_stratum = false;
		opt_extranonce = false;
		break;
	case 1009:
		opt_redirect = false;
		break;
	case 1010:
		allow_getwork = false;
		break;
	case 1011:
		have_gbt = false;
		break;
	case 1012:
		opt_extranonce = false;
		break;
	case 1013:			/* --coinbase-addr */
		pk_script_size = address_to_script(pk_script, sizeof(pk_script), arg);
		if (!pk_script_size) {
			fprintf(stderr, "invalid address -- '%s'\n", arg);
			show_usage_and_exit(1);
		}
		break;
	case 1015:			/* --coinbase-sig */
		if (strlen(arg) + 1 > sizeof(coinbase_sig)) {
			fprintf(stderr, "coinbase signature too long\n");
			show_usage_and_exit(1);
		}
		strcpy(coinbase_sig, arg);
		break;
	case 'f':
		d = atof(arg);
		if (d == 0.)	/* --diff-factor */
			show_usage_and_exit(1);
		opt_diff_factor = d;
		break;
	case 'm':
		d = atof(arg);
		if (d == 0.)	/* --diff-multiplier */
			show_usage_and_exit(1);
		opt_diff_factor = 1.0/d;
		break;
	case 1020:
		v = atoi(arg);
		if (v < -1)
			v = -1;
		if (v > (1<<num_cpus)-1)
			v = -1;
		opt_affinity = v;
		break;
	case 1021:
		v = atoi(arg);
		if (v < 0 || v > 5)	/* sanity check */
			show_usage_and_exit(1);
		opt_priority = v;
		break;
	case 'V':
		show_version_and_exit();
	case 'h':
		show_usage_and_exit(0);
	default:
		show_usage_and_exit(1);
	}
}

void parse_config(json_t *config, char *ref)
{
	int i;
	json_t *val;

	for (i = 0; i < ARRAY_SIZE(options); i++) {
		if (!options[i].name)
			break;

		val = json_object_get(config, options[i].name);
		if (!val)
			continue;
		if (options[i].has_arg && json_is_string(val)) {
			char *s = strdup(json_string_value(val));
			if (!s)
				break;
			parse_arg(options[i].val, s);
			free(s);
		}
		else if (options[i].has_arg && json_is_integer(val)) {
			char buf[16];
			sprintf(buf, "%d", (int)json_integer_value(val));
			parse_arg(options[i].val, buf);
		}
		else if (options[i].has_arg && json_is_real(val)) {
			char buf[16];
			sprintf(buf, "%f", json_real_value(val));
			parse_arg(options[i].val, buf);
		}
		else if (!options[i].has_arg) {
			if (json_is_true(val))
				parse_arg(options[i].val, "");
		}
		else
			applog(LOG_ERR, "JSON option %s invalid",
			options[i].name);
	}
}

static void parse_cmdline(int argc, char *argv[])
{
	int key;

	while (1) {
		key = getopt_long(argc, argv, short_options, options, NULL);

		if (key < 0)
			break;

		parse_arg(key, optarg);
	}
	if (optind < argc) {
		fprintf(stderr, "%s: unsupported non-option argument -- '%s'\n",
			argv[0], argv[optind]);
		show_usage_and_exit(1);
	}
}

#ifndef WIN32
static void signal_handler(int sig)
{
	switch (sig) {
	case SIGHUP:
		applog(LOG_INFO, "SIGHUP received");
		break;
	case SIGINT:
		applog(LOG_INFO, "SIGINT received, exiting");
		proper_exit(0);
		break;
	case SIGTERM:
		applog(LOG_INFO, "SIGTERM received, exiting");
		proper_exit(0);
		break;
	}
}
#else
BOOL WINAPI ConsoleHandler(DWORD dwType)
{
	switch (dwType) {
	case CTRL_C_EVENT:
		applog(LOG_INFO, "CTRL_C_EVENT received, exiting");
		proper_exit(0);
		break;
	case CTRL_BREAK_EVENT:
		applog(LOG_INFO, "CTRL_BREAK_EVENT received, exiting");
		proper_exit(0);
		break;
	default:
		return false;
	}
	return true;
}
#endif

static int thread_create(struct thr_info *thr, void* func)
{
	int err = 0;
	pthread_attr_init(&thr->attr);
	err = pthread_create(&thr->pth, &thr->attr, func, thr);
	pthread_attr_destroy(&thr->attr);
	return err;
}

static void show_credits()
{
	printf("** " PACKAGE_NAME " " PACKAGE_VERSION " (based on cpuminer 2.4.5) **\n");
}

void get_defconfig_path(char *out, size_t bufsize, char *argv0);

static bool detect_fpga()
{
	int i, j, fd;
	
	char *bitstream;
	
	g_fpga_count = 0;
	g_serial_fpga_count = 0;
	g_ztex_fpga_count = 0;

	struct libztex_dev_list **ztex_devices;

	if (opt_use_serial) {

		applog(LOG_DEBUG, "Detect Serial FPGAs...");

		for (i = 0; i < g_serial_device_count; i++) {

			fd = serial_open(serial_fpga_list[i], SERIAL_IO_SPEED, SERIAL_READ_TIMEOUT, true);
			if (fd == -1) {
				applog(LOG_ERR, "ERROR: Unable to find Serial FPGA on Port: %s", serial_fpga_list[i]);
			}
			else {
				g_fpga_count++;
				g_serial_fpga_count++;

				applog(LOG_WARNING, "Detected Serial FPGA on Port: %s", serial_fpga_list[i]);
			}
			close(fd);
		}
	}	

	if (opt_use_ztex) {

		applog(LOG_DEBUG, "Detect ZTEX FPGAs...");

		g_ztex_fpga_count = libztex_scanDevices(&ztex_devices, opt_firmware);
		if ( g_ztex_fpga_count <= 0) {
			applog(LOG_ERR, "ERROR: No ZTEX FGPA Boards Found");
			return false;
		}

		applog(LOG_INFO, "Found %d ZTEX FPGA Boards", g_ztex_fpga_count);

		ztex_info = (struct libztex_device*) calloc(g_ztex_fpga_count, sizeof(struct libztex_device));
		if(!ztex_info) {
			applog(LOG_ERR, "ERROR: Unable To Allocate ZTEX Info");
			return false;
		}

		switch (opt_algo) {
			case ALGO_BLAKE2S:
				bitstream = "ztex_blake2s.bit";
				break;
			case ALGO_DMD_GR:
			case ALGO_GROESTL:
				bitstream = "ztex_groestl.bit";
				break;
			case ALGO_MYR_GR:
				bitstream = "ztex_myr_groestl.bit";
				break;
			case ALGO_BLAKECOIN:
			case ALGO_VCASH:
				bitstream = "ztex_blake256_8.bit";
				break;
			case ALGO_KECCAK256:
				bitstream = "ztex_keccak256_8.bit";
				break;
			case ALGO_KECCAK512:
				bitstream = "ztex_keccak512_8.bit";
				break;
			case ALGO_LYRA2REV2:
				bitstream = "ztex_lyra2rev2.bit";
				break;
			case ALGO_LYRA2Z:
				bitstream = "ztex_lyra2z.bit";
				break;
			case ALGO_NIST5:
				bitstream = "ztex_nist5.bit";
				break;
		}
		
		for (i = 0; i < g_ztex_fpga_count; i++) {

			memcpy(&ztex_info[i], ztex_devices[i]->dev, sizeof(struct libztex_device));

			ztex_info[i].numberOfFpgas = libztex_numberOfFpgas(&ztex_info[i]);;
			ztex_info[i].selectedFpga = -1;

			g_fpga_count++;

			applog(LOG_WARNING,"%s: Found Ztex Board (fpga count = %d), ID #%d", ztex_info[i].repr, ztex_info[i].numberOfFpgas, i);
			
			for (j = 0; j < ztex_info[i].numberOfFpgas; j++) {
			
				if(!libztex_selectFpga(&ztex_info[i], j)) return false;
				libztex_resetFpga(&ztex_info[i]);
				if(!libztex_configureFpga(&ztex_info[i], bitstream)) return false;
				if(!libztex_setFreq(&ztex_info[i], g_ztex_freq)) return false;
				applog(LOG_WARNING, "%s-%d: Successfully configured", ztex_info[i].repr, j);

				nmsleep(200);				
			
			}			
		}

		libztex_freeDevList(ztex_devices);
	}

	if (g_fpga_count == 0) {
		applog(LOG_ERR, "ERROR: No FPGAs Found!");
		return false;
	}

	return true;
}

static bool initialize_serial_miner(void *thr, int serial_fpga_num)
{
	struct thr_info *mythr = thr;
	struct fpga_info *fpga = mythr->fpga;
	char short_name[5];
	
	memset(fpga->name, 0, 11);
	memset(fpga->short_name, 0, 5);

	sprintf(short_name, "SRL%d", serial_fpga_num);
	
	strcpy(fpga->name, "SerialFPGA");
	strcpy(fpga->short_name, short_name);
	fpga->type = FPGA_SERIAL;
//	fpga->device_path = malloc(strlen(serial_fpga_list[serial_fpga_num]) + 1);
//	strcpy(fpga->device_path, serial_fpga_list[serial_fpga_num]);
	fpga->device_fd = -1;
	fpga->timeout = opt_scantime;
	fpga->Hs = 0.000001;	// Default Hs(hashes/sec) to 1MH/s until share is found and hashrate can be calculated
			
	fpga->slot_id = serial_fpga_num;
	fpga->pf_id = FPGA_APP_PF;
	fpga->bar_id = APP_PF_BAR0;
	
	return true;
}

static bool initialize_ztex_miner(void *thr, int ztex_num)
{
	int i;	
	struct thr_info *mythr = thr;
	struct fpga_info *fpga = mythr->fpga;
	char short_name[10];
	
	memset(fpga->short_name, 0, 10);

	sprintf(short_name, "ZTX%d", ztex_num);
	
	memcpy(fpga->name, ztex_info[ztex_num].repr, 20);
	strcpy(fpga->short_name, short_name);
	fpga->type = FPGA_ZTEX;
	fpga->timeout = opt_scantime;
	fpga->ztex_info = &ztex_info[ztex_num];

	fpga->ztex_stats = (struct ztex_stats *) calloc(ztex_info[ztex_num].numberOfFpgas, sizeof(struct ztex_stats));
	
	for(i=0; i<ztex_info[ztex_num].numberOfFpgas; i++) {
		fpga->ztex_stats[i].enabled = true;
		fpga->ztex_stats[i].hashrate = 0.0;
		fpga->ztex_stats[i].freq = g_ztex_freq;
		gettimeofday(&fpga->ztex_stats[i].freq_check_tv, NULL);
	}

	return true;
}

extern void calc_hash(unsigned char *data, const unsigned char *hash)
{
	uint32_t endian_data[20];
	uint32_t *data32 = (uint32_t *)(data);

	swap_endian(endian_data, data32, 80);

	switch (opt_algo) {
		case ALGO_BLAKE2S:
			blake2s_hash((void *)hash, (void *)endian_data);
			break;
		case ALGO_DMD_GR:
		case ALGO_GROESTL:
			groestlhash((void *)hash, (void *)endian_data);
			break;
		case ALGO_MYR_GR:
			myriadhash((void *)hash, (void *)endian_data);
			break;
		case ALGO_BLAKECOIN:
		case ALGO_VCASH:
			blake256_8_hash((void *)hash, (void *)endian_data);
			break;
		case ALGO_KECCAK256:
			keccak256_hash((void *)hash, (void *)endian_data);
			break;
		case ALGO_KECCAK512:
			keccak512_hash((void *)hash, (void *)endian_data);
			break;
		case ALGO_LYRA2REV2:
			lyra2rev2_hash((void *)hash, (void *)endian_data);
			break;
		case ALGO_LYRA2Z:
			lyra2z_hash((void *)hash, (void *)endian_data);
			break;
		case ALGO_NIST5:
			nist5_hash((void *)hash, (void *)endian_data);
			break;
	}
}

extern void calc_midstate(unsigned char *data, const unsigned char *midstate)
{
	uint32_t endian_data[20];
	uint32_t *data32 = (uint32_t *)(data);

	swap_endian(endian_data, data32, 80);

	switch (opt_algo) {
		case ALGO_BLAKE2S:
			blake2s_midstate((void *)midstate, (void *)endian_data);
			break;
		case ALGO_BLAKECOIN:
		case ALGO_VCASH:
			blake256_8_midstate((void *)midstate, (void *)endian_data);
			break;
		default:
			applog(LOG_ERR, "ERROR: Midstate option not supported for this algo");
	}
}
					
static void *serial_miner_thread(void *userdata)
{
	struct thr_info *mythr = userdata;
	struct fpga_info *fpga = mythr->fpga;
	int thr_id = mythr->id;
	struct work work = {{0}};
	int i, rc, fd, ret;
	unsigned char data[80], midstate[32], send_buf[80], nonce_buf[SERIAL_READ_SIZE];
	uint32_t *target;
	bool display_summary = false;

	uint32_t nonce, hash[8];
	int64_t hash_count;
	struct timeval tv_start, tv_finish, elapsed, tv_end, diff;
	
	unsigned char *b = (unsigned char *)send_buf;
	uint32_t *b32 = (uint32_t *)send_buf;
	uint32_t value = 0x00000000;
	uint32_t old_value = 0x00000000;
	uint64_t addr = 0x500;

	// Get PCI Bar Handle To The AWS FPGA
	pci_bar_handle_t pci_bar_handle = PCI_BAR_HANDLE_INIT;

	// attach to the fpga, with a pci_bar_handle out param
	// To attach to multiple slots or BARs, call this function multiple times,
	// saving the pci_bar_handle to specify which address space to interact with in
	// other API calls.
	// This function accepts the slot_id, physical function, and bar number
	rc = fpga_pci_attach(fpga->slot_id, fpga->pf_id, fpga->bar_id, 0, &pci_bar_handle);
	if (rc) {
		applog(LOG_ERR, "Unable to attache to AWS FPGA on slot %s", fpga->slot_id);
		goto out;
	}

	nonce = 0;
	
	while (1) {
		unsigned long hashes_done;
		int rc;

//		if (fpga->device_fd == -1) {
		
//			applog(LOG_DEBUG, "Attemping to Reopen Serial FPGA on %s", fpga->device_path);
//			fd = serial_open(fpga->device_path, SERIAL_IO_SPEED, SERIAL_READ_TIMEOUT, false);
//			if (fd == -1) {
//				applog(LOG_ERR, "Failed to open Serial FPGA on %s", fpga->device_path);
//				nmsleep(5000);

//				applog(LOG_DEBUG, "Attemping to Reopen Serial FPGA on %s", fpga->device_path);
//				fd = serial_open(fpga->device_path, SERIAL_IO_SPEED, SERIAL_READ_TIMEOUT, false);
//				if (fd == -1) {
//					applog(LOG_ERR, "Failed to open Serial FPGA on %s", fpga->device_path);
//					goto out;
//				}
//				else
//				fpga->device_fd = fd;
//			}
//			else
//				fpga->device_fd = fd;
//		}

		if (have_stratum) {
			while (!jsonrpc_2 && time(NULL) >= g_work_time + 120)
				sleep(1);
			stratum_gen_work(&stratum, &work);
		}
		else {
			applog(LOG_ERR, "ERROR: Only Stratum Protocol Has Been Implemented");
			goto out;
		}
		work_restart[thr_id].restart = 0;

		target = (uint32_t *)(work.target);

		if ( g_fpga_use_midstate ) {
			calc_midstate((unsigned char *)work.data, (unsigned char *)midstate);
			memcpy(data, midstate, 32);
			memcpy(data + 32, (unsigned char*)work.data + 64, 12);	// Copy Midstate & Remaining 12 Bytes Of Block Header
		}
		else {
			memcpy(data, (unsigned char*)work.data, 76);
			memcpy(data + 76, (unsigned char*)work.target + 28, 4);  // Used To Pass H7 Target To FPGA
		}

		// Change Endianess On Each 4 Byte Chunk
		swap_endian(send_buf, data, g_fpga_work_len);


		
// Temp Hack For 8x Test
//if(fpga->slot_id > 0)
//		memset(send_buf, 0, 80);
		
//	unsigned char z[] = { 0x07, 0x00, 0x00, 0x00, 0x6B, 0x0F, 0xDD, 0xFD, 0x5B, 0xF7, 0x67, 0x24, 0x62, 0x79, 0x7E, 0x85, 0xC7, 0xF3, 0xA7, 0xD2, 0x39, 0xD7, 0x18, 0x39, 0x0C, 0x1A, 0x99, 0xED, 0xEC, 0xE0, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0E, 0x50, 0xF9, 0xB0, 0xFA, 0xED, 0xCF, 0x11, 0x18, 0x62, 0x4E, 0x1C, 0x23, 0xAC, 0x31, 0x4B, 0x97, 0xDA, 0xA6, 0xBD, 0xFC, 0x73, 0x1C, 0x36, 0xF7, 0x26, 0xBB, 0xEC, 0x7A, 0x87, 0x8C, 0x70, 0x39, 0x6B, 0x4F, 0x5A, 0x11, 0xCD, 0x09, 0x1B, 0x00, 0x00, 0x00, 0x00 };
//	uint32_t *z32 = (uint32_t *)z;


// Temp Dump Header		
		applog(LOG_DEBUG, "Block Header: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n", b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7],b[8],b[9],b[10],b[11],b[12],b[13],b[14],b[15],b[16],b[17],b[18],b[19],b[20],b[21],b[22],b[23],b[24],b[25],b[26],b[27],b[28],b[29],b[30],b[31],b[32],b[33],b[34],b[35],b[36],b[37],b[38],b[39],b[40],b[41],b[42],b[43],b[44],b[45],b[46],b[47],b[48],b[49],b[50],b[51],b[52],b[53],b[54],b[55],b[56],b[57],b[58],b[59],b[60],b[61],b[62],b[63], b[64],b[65],b[66],b[67],b[68],b[69],b[70],b[71],b[72],b[73],b[74],b[75],b[76],b[77],b[78],b[79] );
//		printf("\nDumping Block Header stored in FPGA...\n\n");
		
		// Send Data To FPGA
//		ret = write(fd, send_buf, g_fpga_work_len);

//		if (ret != g_fpga_work_len) {
//			applog(LOG_ERR, "%s: Serial Send Error (ret=%d)", fpga->short_name, ret);
//			close(fpga->device_fd);
//			fpga->device_fd = -1;
//			fpga->Hs = 1;
//		}

		// Send Data To FPGA
		// Break Block Header into 32bit chunks and pass to pci register addresses offset by 4 bytes each time
		addr = UINT64_C(0x504);
		for (i = 0; i < 20; i++) {
//			rc = fpga_pci_poke(pci_bar_handle, addr, b32[i]);
//			rc = fpga_pci_poke(pci_bar_handle, addr, swab32(z32[i]));
			rc = fpga_pci_poke(pci_bar_handle, addr, swab32(b32[i]));
//			rc = fpga_pci_poke(pci_bar_handle, addr, 00000000);
			addr += 4;
		}



// addr = UINT64_C(0x000);
// value = 0x33333333;
// for (i = 0; i < 20; i++) {                
//  rc = fpga_pci_peek(pci_bar_handle, addr, &value);      
//  printf("FPGA returned 0x%x from address 0x%x\n", value, addr);      
//  addr += 4;
// }
		
		hashes_done = 0;
		elapsed.tv_sec = 0;
		elapsed.tv_usec = 0;
		gettimeofday(&tv_start, NULL);

		applog(LOG_DEBUG, "%s: Begin Scan For Nonces", fpga->short_name);
		while (mythr && !work_restart[thr_id].restart) {

			memset(nonce_buf,0,4);
		
			// Check Serial Port For 1/10 Sec For Nonce  
//			ret = read(fd, nonce_buf, SERIAL_READ_SIZE);

			addr = UINT64_C(0x554);
			for (i = 0; i < 10; i++) {
				rc = fpga_pci_peek(pci_bar_handle, addr, &value);
//				value = swab32(value);
//				value = value - 0x1B337BE;
				if (rc) {
					applog(LOG_ERR, "%s: Read error on AWS FPGA slot %d", fpga->short_name, fpga->slot_id);
					continue;
				}
				
				if ((value != 0) && (value != old_value)) {
					nonce = value;
					old_value = value;
					ret = 1;
					addr = UINT64_C(0x050);
					rc = fpga_pci_poke(pci_bar_handle, addr, value);
					rc = fpga_pci_peek(pci_bar_handle, addr, &value);
//					printf("FPGA returned 0x%x from address 0x%x\n", value, addr);
					break;
				}
				ret = 0;
				nmsleep(5);
			}

			// Calculate Elapsed Time
			gettimeofday(&tv_end, NULL);
			timeval_subtract(&elapsed, &tv_end, &tv_start);

			if (ret == 0) {		// No Nonce Found
				if (elapsed.tv_sec >= fpga->timeout) {
					applog(LOG_DEBUG, "%s: End Scan For Nonces - Time = %d sec", fpga->short_name, elapsed.tv_sec);
					break;
				}
				continue;
			}
//			else if (ret < SERIAL_READ_SIZE) {
//				applog(LOG_ERR, "%s: Serial Read Error (ret=%d)", fpga->short_name, ret);
//				close(fpga->device_fd);
//				fpga->device_fd = -1;
//				fpga->Hs = 1;
//				break;
//			}

//			memcpy((char *)&nonce, nonce_buf, SERIAL_READ_SIZE);
//			nonce = swab32(nonce);

			// Calculate Hash Using Nonce By FPGA
			work.data[19] = nonce;
			calc_hash((unsigned char *)work.data, (unsigned char *)hash);

			// Check If Hash < Target Sent To FPGA
			if (swab32(hash[7]) > swab32(target[7])) {
				fpga->hw_errors++;
				applog(LOG_DEBUG, "%s: HW Error (Nonce: %08X, Hash: %08X, Target: %08X)", fpga->short_name, nonce, swab32(hash[7]), swab32(target[7]));
				continue;
			}

			// Update Hashrate
			fpga->Hs = ((double)(elapsed.tv_sec) + ((double)(elapsed.tv_usec))/((double)1000000)) / (double)nonce;
			if(fpga->Hs < 0.000000001)
				fpga->Hs = 0.000000001;

			// Check If Hash < Work Target
			if(fulltest(hash, work.target)) {
				applog(LOG_DEBUG, "%s: Nonce Found - %08X (%5.1fMhz)", fpga->short_name, nonce, (double)(1/(fpga->Hs * 1000000)));
				fpga->submitted++;
				submit_work(mythr, &work);

				// Check If Block Was Found
				if(fulltest(hash, work.block_target)) {
					applog(LOG_NOTICE, "%s: %s***** BLOCK FOUND *****", fpga->short_name, CL_GRN);
					g_block_count++;
				}
			}
			else {
				applog(LOG_DEBUG, "%s: Share above target - %08X (%5.1fMhz)", fpga->short_name, nonce, (double)(1/(fpga->Hs * 1000000)));
			}
		}

		// Estimate Number Of Hashes
		hashes_done = ((double)(elapsed.tv_sec) + ((double)(elapsed.tv_usec))/((double)1000000)) / fpga->Hs;
		fpga->hashrate = hashes_done / (elapsed.tv_sec + elapsed.tv_usec * 1e-6);

		pthread_mutex_lock(&stats_lock);
		thr_hashrates[thr_id] = fpga->hashrate;
		pthread_mutex_unlock(&stats_lock);
		
		// Display FPGA Summary
		if (display_summary != opt_fpga_summary) {
			
			display_summary = opt_fpga_summary;

			applog(LOG_WARNING, "----------------- FPGA Summary for %s -------------------", fpga->device_path);
			applog(LOG_WARNING, "Hash: %-4.2fMh/s  Submitted: %u  HW: %u", fpga->hashrate / 1000000.0, fpga->submitted, fpga->hw_errors);
			applog(LOG_WARNING, "--------------------------------------------------------------------");
		}

	}

out:
	tq_freeze(mythr->q);
	
	pthread_mutex_lock(&stats_lock);
	thr_hashrates[thr_id] = 0;
	pthread_mutex_unlock(&stats_lock);
	
	return NULL;
}



static uint32_t ztex_checkNonce(unsigned char* data)
{
	uint32_t hash[8];
	
	calc_hash(data, (unsigned char *)hash);

	return hash[7];
}

					
static void *ztex_miner_thread(void *userdata)
{
	struct thr_info *mythr = userdata;
	struct fpga_info *fpga = mythr->fpga;
	struct libztex_device *ztex = fpga->ztex_info;
	struct ztex_stats *ztex_stats = fpga->ztex_stats;
	int thr_id = mythr->id;
	struct work *work;
	int i, j, fd, rc, count;
	uint32_t *target;
	bool display_summary = false;

	uint32_t nonce, hash7, golden[2], hash[8];
	struct timeval tv_start, tv_finish, elapsed, tv_end, diff;

	uint32_t golden_nonce1, golden_nonce2;
	uint32_t last_nonce[4], last_golden1[4], last_golden2[4], hw_errors[4];
	bool overflow[4];
	
	unsigned char data[80], send_buf[80], midstate[32];
	unsigned char* b = (unsigned char*)send_buf;

	int num_fpgas = ztex->numberOfFpgas;

	work = (struct work *) calloc(num_fpgas, sizeof(struct work));
	if(!work) {
		applog(LOG_ERR, "calloc failed");
		return;
	}
	
	while (1) {
		
		// Send Data To Be Hashed To Each Chip On FPGA
		for (i=0; i<num_fpgas; i++) {

			// Skip Over Any Disabled FPGAs
			if(!ztex_stats[i].enabled)
				continue;
		
			if (have_stratum) {
				while (!jsonrpc_2 && time(NULL) >= g_work_time + 120)
					nmsleep(10);
				stratum_gen_work(&stratum, &work[i]);
			}
			else {
				applog(LOG_ERR, "ERROR: Only Stratum Protocol Has Been Implemented");
				goto out;
			}
			
			target = (uint32_t *)(work[i].target);

			if ( g_fpga_use_midstate ) {
				calc_midstate((unsigned char *)work[i].data, (unsigned char *)midstate);
				memcpy(data, midstate, 32);
				memcpy(data + 32, (unsigned char*)work[i].data + 64, 12);	// Copy Midstate & Remaining 12 Bytes Of Block Header
				
				if (opt_algo == ALGO_BLAKE2S) {
					swap_endian(send_buf, midstate, 32);
					memcpy(send_buf + 32, (unsigned char*)work[i].data + 64, 12);  // Blake2s uses LE data
				}
				else
					swap_endian(send_buf, data, g_fpga_work_len);
				
			}
			else {
				memcpy(data, (unsigned char*)work[i].data, 76);
				memcpy(data + 76, (unsigned char*)work[i].target + 28, 4);  // Used To Pass H7 Target To FPGA
				swap_endian(send_buf, data, g_fpga_work_len);
			}

			applog(LOG_DEBUG, "%s BUF_1: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x", fpga->short_name, b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7],b[8],b[9],b[10],b[11],b[12],b[13],b[14],b[15],b[16],b[17],b[18],b[19],b[20],b[21],b[22],b[23],b[24],b[25],b[26],b[27],b[28],b[29],b[30],b[31],b[32],b[33],b[34],b[35],b[36],b[37],b[38],b[39]);
			applog(LOG_DEBUG, "%s BUF_2: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x", fpga->short_name, b[40],b[41],b[42],b[43],b[44],b[45],b[46],b[47],b[48],b[49],b[50],b[51],b[52],b[53],b[54],b[55],b[56],b[57],b[58],b[59],b[60],b[61],b[62],b[63],b[64],b[65],b[66],b[67],b[68],b[69],b[70],b[71],b[72],b[73],b[74],b[75],b[76],b[77],b[78],b[79]);

			// Send Work To FPGA
			libztex_selectFpga(ztex, i);
			rc = libztex_sendData(ztex, send_buf, g_fpga_work_len);
			if (rc < 0) {
				applog(LOG_ERR, "%s: Failed to send hash data with err %d, retrying", fpga->short_name, rc);
				nmsleep(500);
				rc = libztex_sendData(ztex, send_buf, g_fpga_work_len);
				if (rc < 0) {
					ztex_stats[i].enabled = false;
					continue;
				}
			}
			
			overflow[i] = false;
			last_golden1[i] = 0;
			last_golden2[i] = 0;
			last_nonce[i] = 0;
			hw_errors[i] = 0;
		
		}
		
		work_restart[thr_id].restart = 0;
		count = 0;
		
		gettimeofday(&tv_start, NULL);

		applog(LOG_DEBUG, "%s: entering poll loop", fpga->short_name);
		while (mythr && !work_restart[thr_id].restart) {
			count++;

			int sleepcount = 0;
			while (work_restart[thr_id].restart == 0 && sleepcount < 25) {
				nmsleep(10);
				sleepcount += 1;
			}

			// Check If New Work Is Available
			if (work_restart[thr_id].restart) {
				applog(LOG_DEBUG, "%s: New work detected", fpga->short_name);
				break;
			}
			
			for (i=0; i < num_fpgas; i++) {

				// Skip Any Disabled FPGA Or If All Nonces Have Been Checked
				if(!ztex_stats[i].enabled || overflow[i])
					continue;
			
				// Read Results From FPGA
				libztex_selectFpga(ztex, i);
				rc = libztex_readData(ztex, &nonce, &hash7, golden);
				if (rc < 0) {
					applog(LOG_ERR, "ERROR: Failed To Read Data From %s-%d (rc=%d), retrying...", fpga->short_name, i, rc);
					nmsleep(500);
					rc = libztex_readData(ztex, &nonce, &hash7, golden);
					if (rc < 0) {
						ztex_stats[i].enabled = false;
						continue;
					}
				}

				// Get Rid of FPGA Noise
				if ((nonce == 0x00000000) || (nonce == hash7))
					continue;

				// Check For Hardware Errors On The FPGA
				work[i].data[19] = nonce;
				if (ztex_checkNonce((unsigned char*)work[i].data) != hash7) {
					if (count > 2) {	// Only Count Errors After The First 500ms Of Work Being Sent To FPGA
						hw_errors[i]++;
						ztex_stats[i].hw_errors++;
						applog(LOG_DEBUG, "%s%d: Check Nonce Failed - Nonce: %08X, Hash: %08X, Expected: %08X", fpga->short_name, i, nonce, ztex_checkNonce((unsigned char*)work[i].data), hash7);
					}
					continue;
				}

				// Check If FPGA Has Processed All Nonces For The Work
				if ( nonce < last_nonce[i] ) {
					applog(LOG_DEBUG, "%s%d: Overflow - Nonce=%08X, Last=%08X", fpga->short_name, i, nonce, last_nonce[i]);
					overflow[i] = true;
					continue;
				}
				else
					last_nonce[i] = nonce;

				// Check If Golden Nonce Found
				for (j=0; j < 2; j++) {
					
					if ((golden[j] != 0) && (golden[j] != last_golden1[i]) && (golden[j] != last_golden2[i])) {

						last_golden2[i] = last_golden1[i];
						last_golden1[i] = golden[j];

						work[i].data[19] = golden[j];
						calc_hash((unsigned char *)work[i].data, (unsigned char *)hash);
					
						// Check If Hash < Target Sent To FPGA
						if (swab32(hash[7]) > swab32(target[7])) {
							hw_errors[i]++;
							fpga->hw_errors++;
							ztex_stats[i].hw_errors++;
							applog(LOG_INFO, "%s-%d: HW Error (Nonce: %08x, Hash: %08X, Target: %08X)", fpga->short_name, i, golden[j], swab32(hash[7]), swab32(target[7]));
							continue;
						}
					
						// Check If Hash < Work Target
						if(fulltest(hash, work[i].target)) {
							applog(LOG_DEBUG, "%s-%d: Submit Nonce - %08X (%1.1fMhz)", fpga->short_name, i, golden[j], ztex_stats[i].hashrate/1000000.0);
							ztex_stats[i].submitted++;
							submit_work(mythr, &work[i]);

							// Check If Block Was Found
							if(fulltest(hash, work[i].block_target)) {
								applog(LOG_NOTICE, "%s-%d: %s***** BLOCK FOUND *****", fpga->short_name, i, CL_GRN);
								g_block_count++;
							}
						}
						else {
							applog(LOG_DEBUG, "%s-%d: Share Above Target - %08X (%1.1f MH/s)", fpga->short_name, i, golden[j], ztex_stats[i].hashrate/1000000.0);
						}
					}
				}
			}
				
			// Calculate Elapsed Time
			gettimeofday(&tv_end, NULL);
			timeval_subtract(&elapsed, &tv_end, &tv_start);

			// Calculate Hashrates
			fpga->hashrate = 0.0;
			for (i=0; i < num_fpgas; i++) {
				ztex_stats[i].hashrate = (double)last_nonce[i] / ((double)(elapsed.tv_sec) + ((double)(elapsed.tv_usec))/((double)1000000));
				fpga->hashrate += ztex_stats[i].hashrate;
			}

			pthread_mutex_lock(&stats_lock);
			thr_hashrates[thr_id] = fpga->hashrate;
			pthread_mutex_unlock(&stats_lock);
			
			if (elapsed.tv_sec >= fpga->timeout) {
				applog(LOG_DEBUG, "%s: End Scan For Nonces - Time = %d sec", fpga->short_name, elapsed.tv_sec);
				break;
			}
			
		}

		// Check & Adjust ZTEX Clock Frequency
		for (i=0; i < num_fpgas; i++) {
			if (ztex_stats[i].enabled && ztex_stats[i].hashrate > 0) {
				
				// Ellapsed Time Since Last Frequency Check
				timeval_subtract(&elapsed, &tv_end, &ztex_stats[i].freq_check_tv);
				
				// Restart Frequency Check Error Count Every 2 Minutes
				if(elapsed.tv_sec > 120) {

					// Increase Frequency If No Error Found In Last 2 Minutes
					if(opt_auto_freq && !ztex_stats[i].max_freq_found && ztex_stats[i].freq_check_errors == 0 && hw_errors[i] == 0) {
						ztex_stats[i].freq++;
						libztex_selectFpga(ztex, i);
						libztex_setFreq(ztex, ztex_stats[i].freq);
					}

					ztex_stats[i].freq_check_errors = hw_errors[i];
					gettimeofday(&ztex_stats[i].freq_check_tv, NULL);
				}
				else {
					ztex_stats[i].freq_check_errors += hw_errors[i];
				}
				
				// Decrease Frequency If More Than 1 Error In Last 2 Minutes
				if(ztex_stats[i].freq_check_errors > 1) {
					if(!ztex_stats[i].max_freq_found) {
						ztex_stats[i].max_freq_found = true;
						ztex_stats[i].hw_errors = 0;
					}
					ztex_stats[i].freq--;
					libztex_selectFpga(ztex, i);
					libztex_setFreq(ztex, ztex_stats[i].freq);
					ztex_stats[i].freq_check_errors = 0;
					gettimeofday(&ztex_stats[i].freq_check_tv, NULL);
				}
			}
		}
		
		// Display FPGA Summary
		if (display_summary != opt_fpga_summary) {
			
			display_summary = opt_fpga_summary;

			applog(LOG_WARNING, "----------------- FPGA Summary for %s -----------------", fpga->name);
			
			for (i=0; i < num_fpgas; i++) {

				if(ztex_stats[i].enabled)
					applog(LOG_WARNING, "Hash: %-4.2f Mh/s  Freq: %-3u Mhz  Submitted: %u  HW: %u", ztex_stats[i].hashrate / 1000000.0, (ztex_stats[i].freq + 1) * 4, ztex_stats[i].submitted, ztex_stats[i].hw_errors);
				else
					applog(LOG_WARNING, "Hash: DISABLED     Freq: %-3u Mhz  Submitted: %u  HW: %u", ztex_stats[i].hashrate / 1000000.0, (ztex_stats[i].freq + 1) * 4, ztex_stats[i].submitted, ztex_stats[i].hw_errors);
					
			}

			applog(LOG_WARNING, "--------------------------------------------------------------------");
		}
	}

out:
	libztex_destroy_device(ztex);
	tq_freeze(mythr->q);
	
	return NULL;
}

static double ConvertBitsToDouble(unsigned int nBits)
{
    int nShift = (nBits >> 24) & 0xff;

    double dDiff =
        (double)0x0000ffff / (double)(nBits & 0x00ffffff);

    while (nShift < 29)
    {
        dDiff *= 256.0;
        nShift++;
    }
    while (nShift > 29)
    {
        dDiff /= 256.0;
        nShift--;
    }

    return dDiff;
}

static void *key_monitor_thread(void *userdata)
{
	struct timeval now;

	double hashrate, network_difficulty, block_difficulty, diff_factor;
	int i, ch, day, hour, min, sec, total_sec;
	
	switch (opt_algo) {
		case ALGO_DMD_GR:
		case ALGO_GROESTL:
		case ALGO_MYR_GR:
			diff_factor = 256.0 * opt_diff_factor;
			break;
		default:
			diff_factor = opt_diff_factor;
	}
	
	while(true)
	{
		nmsleep(100);
		ch = getchar();
		ch = toupper( ch );
		if (ch == '\n')
			continue;

		switch(ch)
		{
		case 'S':
			{
				gettimeofday(&now, NULL);
				total_sec = now.tv_sec - g_miner_start_time.tv_sec;
				day  = total_sec / 3600 / 24;
				hour = total_sec / 3600 - day*24;
				min  = total_sec / 60 - (day*24 + hour)*60;
				sec  = total_sec % 60;

				applog(LOG_WARNING, "************************** Mining Summary **************************");
				
				if (have_stratum)
				{
					struct stratum_ctx *sctx = &stratum;
					pthread_mutex_lock(&sctx->work_lock);
					network_difficulty = ConvertBitsToDouble(swab32(le32dec(sctx->job.nbits)));
					pthread_mutex_unlock(&sctx->work_lock);

					block_difficulty = stratum_diff / diff_factor;

				}
				
				applog(LOG_WARNING, "Hash: %1.2f Mh/s  A: %u  R: %u (%1.2f%%)  HW: %u  BF: %d"
					,(double)global_hashrate/1000000.0
					,accepted_count
					,rejected_count
					,100.0 * accepted_count / (accepted_count + rejected_count)
					,0
					,g_block_count );
				applog(LOG_WARNING, "Net Diff: %1.3f, Block Diff: %1.3f  Run Time: %02d Days %02d:%02d:%02d", g_net_diff, block_difficulty, day, hour, min, sec);

				applog(LOG_WARNING, "********************************************************************");

			}
			break;
		case 'D':
			opt_debug = !opt_debug;
			applog(LOG_WARNING, "Debug Mode: %s", opt_debug ? "On" : "Off");
			break;
		case 'F':
			opt_fpga_summary = !opt_fpga_summary;
			break;
		case 'Q':
			opt_quiet = !opt_quiet;
			applog(LOG_WARNING, "Quiet Mode: %s", opt_quiet ? "On" : "Off");
			break;
		}
	}
	return 0;
}


int main(int argc, char *argv[]) {
	struct thr_info *thr;
	long flags;
	int i, rc, err, thr_idx, slot_id;

	pthread_mutex_init(&applog_lock, NULL);

	show_credits();

	rpc_user = strdup("");
	rpc_pass = strdup("");
	opt_api_allow = strdup("127.0.0.1"); /* 0.0.0.0 for all ips */

#if defined(WIN32)
	SYSTEM_INFO sysinfo;
	GetSystemInfo(&sysinfo);
	num_cpus = sysinfo.dwNumberOfProcessors;
#elif defined(_SC_NPROCESSORS_CONF)
	num_cpus = sysconf(_SC_NPROCESSORS_CONF);
#elif defined(CTL_HW) && defined(HW_NCPU)
	int req[] = { CTL_HW, HW_NCPU };
	size_t len = sizeof(num_cpus);
	sysctl(req, 2, &num_cpus, &len, NULL, 0);
#else
	num_cpus = 1;
#endif
	if (num_cpus < 1)
		num_cpus = 1;

	/* parse command line */
	parse_cmdline(argc, argv);

	if (!rpc_url) {
		// try default config file in binary folder
		char defconfig[MAX_PATH] = { 0 };
		get_defconfig_path(defconfig, MAX_PATH, argv[0]);
		if (strlen(defconfig)) {
			if (opt_debug)
				applog(LOG_DEBUG, "Using config %s", defconfig);
			parse_arg('c', defconfig);
			parse_cmdline(argc, argv);
		}
	}

	if (!opt_n_threads && opt_use_cpu)
		opt_n_threads = num_cpus;
	if (!opt_n_threads)
		opt_n_threads = 1;

	
	if(!opt_use_cpu)
		g_miner_count = 0;
	else
		g_miner_count = opt_n_threads;

	// Detect Serial & ZTEX FGPAs Connected To The Miner
//	if(opt_use_serial || opt_use_ztex) {
//		err = libusb_init(NULL);
//		if (err) {
//			applog(LOG_ERR, "ERROR: libusb_init() Failed To Initialize (%d)", err);
//			return 1;
//		}
//		if(!detect_fpga()) {
//			return 1;
//		}
//	}

	// Hardcode Miner To Reuse Serial Thread For 1 FPGA
	opt_use_serial = true;
	opt_use_ztex = false;
	opt_use_cpu = false;
//	g_serial_fpga_count = 1;
//	g_fpga_count = 1;
	g_serial_fpga_count = opt_n_threads;
	g_fpga_count = opt_n_threads;
	
	applog(LOG_DEBUG, "Initializing AWS FGPA");
	rc = fpga_pci_init();
	if (rc) {
		applog(LOG_ERR, "Unable to initialize AWS FGPA");
		return 1;
	}
	
	for (i = 0; i < g_serial_fpga_count; i++) {
		applog(LOG_DEBUG, "Checking AWS FGPA on slot %d", i);
		rc = check_afi_ready(i);
		if (rc) {
			applog(LOG_ERR, "AWS FGPA on slot %d is not ready", i);
			return 1;
		}
	}

	g_miner_count += g_fpga_count;

	switch (opt_algo) {
		case ALGO_BLAKE2S:
		case ALGO_BLAKECOIN:
		case ALGO_VCASH:
			g_fpga_use_midstate = true;
			g_fpga_work_len = 44;
			break;
		default:
			g_fpga_use_midstate = false;
			g_fpga_work_len = 80;
	}
	
	if (!rpc_url) {
		fprintf(stderr, "%s: no URL supplied\n", argv[0]);
		show_usage_and_exit(1);
	}

	if (!rpc_userpass) {
		rpc_userpass = (char*) malloc(strlen(rpc_user) + strlen(rpc_pass) + 2);
		if (!rpc_userpass)
			return 1;
		sprintf(rpc_userpass, "%s:%s", rpc_user, rpc_pass);
	}

	pthread_mutex_init(&stats_lock, NULL);
	pthread_mutex_init(&g_work_lock, NULL);
	pthread_mutex_init(&rpc2_job_lock, NULL);
	pthread_mutex_init(&rpc2_login_lock, NULL);
	pthread_mutex_init(&stratum.sock_lock, NULL);
	pthread_mutex_init(&stratum.work_lock, NULL);

	flags = strncmp(rpc_url, "https:", 6)
	        ? (CURL_GLOBAL_ALL & ~CURL_GLOBAL_SSL)
	        : CURL_GLOBAL_ALL;
	if (curl_global_init(flags)) {
		applog(LOG_ERR, "CURL initialization failed");
		return 1;
	}

#ifndef WIN32
	/* Always catch Ctrl+C */
	signal(SIGINT, signal_handler);
#else
	SetConsoleCtrlHandler((PHANDLER_ROUTINE)ConsoleHandler, TRUE);

if (opt_priority > 0) {
		DWORD prio = NORMAL_PRIORITY_CLASS;
		switch (opt_priority) {
		case 1:
			prio = BELOW_NORMAL_PRIORITY_CLASS;
			break;
		case 3:
			prio = ABOVE_NORMAL_PRIORITY_CLASS;
			break;
		case 4:
			prio = HIGH_PRIORITY_CLASS;
			break;
		case 5:
			prio = REALTIME_PRIORITY_CLASS;
		}
		SetPriorityClass(GetCurrentProcess(), prio);
	}
#endif
	if (opt_affinity != -1) {
		if (!opt_quiet)
			applog(LOG_DEBUG, "Binding process to cpu mask %x", opt_affinity);
		affine_to_cpu_mask(-1, opt_affinity);
	}

	work_restart = (struct work_restart*) calloc(g_miner_count, sizeof(*work_restart));
	if (!work_restart)
		return 1;

	thr_info = (struct thr_info*) calloc(g_miner_count + 5, sizeof(*thr));
	if (!thr_info)
		return 1;

	thr_hashrates = (double *) calloc(g_miner_count, sizeof(double));
	if (!thr_hashrates)
		return 1;

	/* init workio thread info */
	work_thr_id = g_miner_count;
	thr = &thr_info[work_thr_id];
	thr->id = work_thr_id;
	thr->q = tq_new();
	if (!thr->q)
		return 1;

	/* start work I/O thread */
	if (thread_create(thr, workio_thread)) {
		applog(LOG_ERR, "work thread create failed");
		return 1;
	}

	/* ESET-NOD32 Detects these 2 thread_create... */
	if (want_longpoll && !have_stratum) {
		/* init longpoll thread info */
		longpoll_thr_id = g_miner_count + 1;
		thr = &thr_info[longpoll_thr_id];
		thr->id = longpoll_thr_id;
		thr->q = tq_new();
		if (!thr->q)
			return 1;

		/* start longpoll thread */
		err = thread_create(thr, longpoll_thread);
		if (err) {
			applog(LOG_ERR, "long poll thread create failed");
			return 1;
		}
	}
	if (want_stratum) {
		/* init stratum thread info */
		stratum_thr_id = g_miner_count + 2;
		thr = &thr_info[stratum_thr_id];
		thr->id = stratum_thr_id;
		thr->q = tq_new();
		if (!thr->q)
			return 1;

		/* start stratum thread */
		err = thread_create(thr, stratum_thread);
		if (err) {
			applog(LOG_ERR, "stratum thread create failed");
			return 1;
		}
		if (have_stratum)
			tq_push(thr_info[stratum_thr_id].q, strdup(rpc_url));
	}

	if (opt_api_listen) {
		/* api thread */
		api_thr_id = g_miner_count + 3;
		thr = &thr_info[api_thr_id];
		thr->id = api_thr_id;
		thr->q = tq_new();
		if (!thr->q)
			return 1;
		err = thread_create(thr, api_thread);
		if (err) {
			applog(LOG_ERR, "api thread create failed");
			return 1;
		}
	}

	applog(LOG_INFO, "Attempting to start %d miner threads using '%s' algorithm", g_miner_count, algo_names[opt_algo]);
	thr_idx = 0;
	
	// Start CPU Mining Threads
	if (opt_use_cpu) {
		for (i = 0; i < opt_n_threads; i++) {
			thr = &thr_info[thr_idx];

			thr->id = thr_idx++;
			thr->q = tq_new();
			if (!thr->q)
				return 1;

			err = thread_create(thr, miner_thread);
			if (err) {
				applog(LOG_ERR, "thread %d create failed", i);
				return 1;
			}
		}
		applog(LOG_INFO, "\t%d CPU miner threads started.", opt_n_threads);
	}

	// Start AWS FPGA Mining Threads
	if (opt_use_serial) {
		for (i = 0; i < g_serial_fpga_count; i++) {
			thr = &thr_info[thr_idx];

			thr->id = thr_idx++;
			thr->q = tq_new();
			if (!thr->q)
				return 1;

			thr->fpga = calloc(1, sizeof(struct fpga_info));
			if ( !thr->fpga ) {
				applog(LOG_ERR, "ERROR: Unable to allocate AWS FPGA Info");
				return 1;
			}
			
			initialize_serial_miner(thr, i);

			err = thread_create(thr, serial_miner_thread);
			if (err) {
				applog(LOG_ERR, "ERROR: AWS FPGA minner thread %d create failed", i);
				return 1;
			}
		}
		applog(LOG_INFO, "\t%d AWS FPGA miner threads started.", g_serial_fpga_count);
	}
	
	
	// Start Serial FPGA Mining Threads
//	if (opt_use_serial) {
//		for (i = 0; i < g_serial_fpga_count; i++) {
//			thr = &thr_info[thr_idx];

//			thr->id = thr_idx++;
//			thr->q = tq_new();
//			if (!thr->q)
//				return 1;

//			thr->fpga = calloc(1, sizeof(struct fpga_info));
//			if ( !thr->fpga ) {
//				applog(LOG_ERR, "ERROR: Unable to allocate Serial FPGA Info");
//				return 1;
//			}
			
//			initialize_serial_miner(thr, i);

//			err = thread_create(thr, serial_miner_thread);
//			if (err) {
//				applog(LOG_ERR, "ERROR: Serial FPGA minner thread %d create failed", i);
//				return 1;
//			}
//		}
//		applog(LOG_INFO, "\t%d Serial FPGA miner threads started.", g_serial_fpga_count);
//	}
	
	// Start ZTEX FPGA Mining Threads
	if (opt_use_ztex) {
		for (i = 0; i < g_ztex_fpga_count; i++) {
			thr = &thr_info[thr_idx];

			thr->id = thr_idx++;
			thr->q = tq_new();
			if (!thr->q)
				return 1;

			thr->fpga = calloc(1, sizeof(struct fpga_info));
			if ( !thr->fpga ) {
				applog(LOG_ERR, "ERROR: Unable to allocate ZTEX FPGA Info");
				return 1;
			}
			
			initialize_ztex_miner(thr, i);

			err = thread_create(thr, ztex_miner_thread);
			if (err) {
				applog(LOG_ERR, "ERROR: ZTEX FPGA miner thread %d create failed", i);
				return 1;
			}
		}
		gettimeofday(&g_miner_start_time, NULL);
		applog(LOG_INFO, "\t%d ZTEX FPGA miner threads started.", g_ztex_fpga_count);
	}

	// Start Mining Summary Thread
	thr = &thr_info[g_miner_count + 4];
	thr->id = g_miner_count + 4;
	thr->q = tq_new();
	if (!thr->q)
		return 1;
	if (thread_create(thr, key_monitor_thread)) {
		applog(LOG_ERR, "key monitor thread create failed");
		return 1;
	}
	
	// Main Loop - Wait for workio thread to exit
	pthread_join(thr_info[work_thr_id].pth, NULL);

	applog(LOG_WARNING, "workio thread dead, exiting.");

	return 0;
}
