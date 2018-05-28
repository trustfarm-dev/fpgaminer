/**
 *   libztex.h - headers for Ztex 1.15x fpga board support library
 *
 *   Copyright (c) 2012 nelisky.btc@gmail.com
 *
 *   This work is based upon the Java SDK provided by ztex which is
 *   Copyright (C) 2009-2011 ZTEX GmbH.
 *   http://www.ztex.de
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License version 2 as
 *   published by the Free Software Foundation.
 *
 *   This program is distributed in the hope that it will be useful, but
 *   WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *   General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, see http://www.gnu.org/licenses/.
**/
#ifndef __LIBZTEX_H__
#define __LIBZTEX_H__

#include <libusb.h>

#define LIBZTEX_MAX_DESCRIPTORS 512
#define LIBZTEX_SNSTRING_LEN 10

#define LIBZTEX_IDVENDOR 0x221A
#define LIBZTEX_IDPRODUCT 0x0100

struct libztex_device {
	int16_t fpgaNum;
	struct libusb_device_descriptor descriptor;
	libusb_device_handle *hndl; 
	unsigned char usbbus;
	unsigned char usbaddress;
	unsigned char snString[LIBZTEX_SNSTRING_LEN+1];
	unsigned char productId[4];
	unsigned char fwVersion;
	unsigned char interfaceVersion;
	unsigned char interfaceCapabilities[6];
	unsigned char moduleReserved[12];
	int16_t numberOfFpgas;
	int selectedFpga;
	char repr[20];
};

struct libztex_dev_list { 
	struct libztex_device *dev;
	struct libztex_dev_list *next;
};

static int libztex_get_string_descriptor_ascii(libusb_device_handle *dev, uint8_t desc_index, unsigned char *data, int length);
static bool libztex_firmwareReset(struct libusb_device_handle *hndl, bool enable);
static enum check_result libztex_checkDevice(struct libusb_device *dev, bool force_firmware);
static bool libztex_checkCapability(struct libztex_device *ztex, int i, int j);
static char libztex_detectBitstreamBitOrder(const unsigned char *buf, int size);
static void libztex_swapBits(unsigned char *buf, int size);
static bool libztex_getConfigured(struct libztex_device *ztex);
static int libztex_prepare_device(struct libusb_device *dev, struct libztex_device** ztex);
extern int libztex_scanDevices(struct libztex_dev_list*** devs_p, bool force_firmware);
extern bool libztex_configureFpga(struct libztex_device *ztex, const char* bitstream);
extern void libztex_freeDevList(struct libztex_dev_list **devs);
extern int libztex_numberOfFpgas(struct libztex_device *ztex);
extern bool libztex_selectFpga(struct libztex_device *ztex, int fpgaNum);
extern bool libztex_setFreq(struct libztex_device *ztex, int freq);
extern int libztex_sendData(struct libztex_device *ztex, unsigned char *sendbuf, int len);
extern int libztex_readData(struct libztex_device *ztex, uint32_t *nonce, uint32_t *hash7, uint32_t *golden);
extern int libztex_resetFpga(struct libztex_device *ztex);
extern int libztex_suspend(struct libztex_device *ztex);
extern void libztex_destroy_device(struct libztex_device* ztex);

#endif /* __LIBZTEX_H__ */
