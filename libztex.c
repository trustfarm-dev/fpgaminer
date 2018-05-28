/**
 *   libztex.c - Ztex 1.15x/1.15y fpga board support library
 *
 *   Copyright (c) 2012 nelisky.btc@gmail.com
 *   Copyright (c) 2012 Denis Ahrens <denis@h3q.com>
 *   Copyright (c) 2012 Peter Stuge <peter@stuge.se>
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "miner.h"
#include "fpgautils.h"
#include "libztex.h"

//* Capability index for EEPROM support.
#define CAPABILITY_EEPROM 0,0
//* Capability index for FPGA configuration support. 
#define CAPABILITY_FPGA 0,1
//* Capability index for FLASH memory support.
#define CAPABILITY_FLASH 0,2
//* Capability index for DEBUG helper support.
#define CAPABILITY_DEBUG 0,3
//* Capability index for AVR XMEGA support.
#define CAPABILITY_XMEGA 0,4
//* Capability index for AVR XMEGA support.
#define CAPABILITY_HS_FPGA 0,5
//* Capability index for AVR XMEGA support.
#define CAPABILITY_MAC_EEPROM 0,6
//* Capability index for multi FPGA support.
#define CAPABILITY_MULTI_FPGA 0,7

static int libztex_get_string_descriptor_ascii(libusb_device_handle *dev, uint8_t desc_index, unsigned char *data, int length)
{
	int i, cnt;
	uint16_t langid;
	unsigned char buf[260];

	/* We open code string descriptor retrieval and ASCII decoding here
	 * in order to work around that libusb_get_string_descriptor_ascii()
	 * in the FreeBSD libusb implementation hits a bug in ZTEX firmware,
	 * where the device returns more bytes than requested, causing babble,
	 * which makes FreeBSD return an error to us.
	 *
	 * Avoid the mess by doing it manually the same way as libusb-1.0.
	 */

	cnt = libusb_control_transfer(dev, LIBUSB_ENDPOINT_IN,
	    LIBUSB_REQUEST_GET_DESCRIPTOR, (LIBUSB_DT_STRING << 8) | 0,
	    0x0000, buf, sizeof(buf), 1000);
	if (cnt < 0) {
		applog(LOG_ERR, "%s: Failed to read LANGIDs: %d", __func__, cnt);
		return cnt;
	}

	langid = libusb_le16_to_cpu(((uint16_t *)buf)[1]);

	cnt = libusb_control_transfer(dev, LIBUSB_ENDPOINT_IN,
	    LIBUSB_REQUEST_GET_DESCRIPTOR, (LIBUSB_DT_STRING << 8) | desc_index,
	    langid, buf, sizeof(buf), 1000);
	if (cnt < 0) {
		applog(LOG_ERR, "%s: Failed to read string descriptor: %d", __func__, cnt);
		return cnt;
	}

	/* num chars = (all bytes except bLength and bDescriptorType) / 2 */
	for (i = 0; i <= (cnt - 2) / 2 && i < length-1; i++)
		data[i] = buf[2 + i*2];

	data[i] = 0;

	return LIBUSB_SUCCESS;
}

enum check_result
{
	CHECK_ERROR,
	CHECK_IS_NOT_ZTEX,
	CHECK_OK,
	CHECK_RESCAN,
};

static bool libztex_firmwareReset(struct libusb_device_handle *hndl, bool enable)
{
	uint8_t reset = enable;
	int cnt = libusb_control_transfer(hndl, 0x40, 0xA0, 0xE600, 0, &reset, 1, 1000);
	if (cnt < 0)
	{
		applog(LOG_ERR, "Ztex reset %d failed: %d", enable, cnt);
		return 1;
	}

	return 0;
}

static enum check_result libztex_checkDevice(struct libusb_device *dev, bool force_firmware)
{
	FILE *fp = NULL;
	libusb_device_handle *hndl = NULL;
	struct libusb_device_descriptor desc;
	int ret = CHECK_ERROR, err, cnt;
	size_t got_bytes, length;
	unsigned char buf[64], *fw_buf;
	unsigned int i;
	char *firmware = "ztex_ufm1_15y1.bin";

	err = libusb_get_device_descriptor(dev, &desc);
	if (unlikely(err != 0)) {
		applog(LOG_ERR, "Unable to open read descriptor with error %d", err);
		return CHECK_ERROR;
	}

	if (desc.idVendor != LIBZTEX_IDVENDOR || desc.idProduct != LIBZTEX_IDPRODUCT) {
		applog(LOG_DEBUG, "Not a ZTEX device %04x:%04x", desc.idVendor, desc.idProduct);
		return CHECK_IS_NOT_ZTEX;
	}

	err = libusb_open(dev, &hndl);
	if (err != LIBUSB_SUCCESS) {
		applog(LOG_ERR, "Unable to open ZTEX device: %d", err);
		goto done;
	}

	cnt = libusb_control_transfer(hndl, 0xc0, 0x22, 0, 0, buf, 40, 500);
	if (unlikely(cnt < 0)) {
		applog(LOG_ERR, "Unable to read ztex descriptor with err %d", cnt);
		goto done;
	}

	if (buf[0] != 40 || buf[1] != 1 || buf[2] != 'Z' || buf[3] != 'T' || buf[4] != 'E' || buf[5] != 'X') {
		applog(LOG_ERR, "Error reading ztex descriptor");
		goto done;
	}

	if (buf[6] != 10)
	{
		ret = CHECK_IS_NOT_ZTEX;
		goto done;
	}

	if (buf[7] != 15) {
		applog(LOG_ERR, "\n\nThis miner only supports ZTEX 1.15y\n");
		ret = CHECK_IS_NOT_ZTEX;
		goto done;
	}

	// Check If Firmware Is Installed
	if (!force_firmware && buf[8] != 0) {
		ret = CHECK_OK;
		goto done;
	}

	applog(LOG_ERR, "No mining Firmware found...updating ZTEX with '%s'", firmware);

	fp = open_bitstream(firmware);
	if (!fp) {
		applog(LOG_ERR, "Unable to open firmware file '%s'", firmware);
		goto done;
	}

	if (0 != fseek(fp, 0, SEEK_END)) {
		applog(LOG_ERR, "Unable to read firmware file '%s'", firmware);
		goto done;
	}

	length = ftell(fp);
	rewind(fp);
	fw_buf = malloc(length);
	if (!fw_buf) {
		applog(LOG_ERR, "Unable to allocate memory for firmware file");
		goto done;
	}

	got_bytes = fread(fw_buf, 1, length, fp);
	fclose(fp);
	fp = NULL;

	if (got_bytes < length) {
		applog(LOG_ERR, "Incomplete firmware read: %zu of %zu bytes", got_bytes, length);
		goto done;
	}

	if (libztex_firmwareReset(hndl, true))
		goto done;

	for (i = 0; i < length; i+= 256) {
		// firmware wants data in small chunks like 256 bytes
		int numbytes = (length - i) < 256 ? (length - i) : 256;
		int k = libusb_control_transfer(hndl, 0x40, 0xA0, i, 0, fw_buf + i, numbytes, 1000);
		if (k < numbytes)
		{
			applog(LOG_ERR, "Failed to write firmware at %d with err: %d", i, k);
			goto done;
		}
	}

	if (libztex_firmwareReset(hndl, false))
		goto done;

	applog(LOG_ERR, "Firmware update complete");
	ret = CHECK_RESCAN;

done:
	if (fp)
		fclose(fp);
	if (hndl)
		libusb_close(hndl);
	return ret;
}

static bool libztex_checkCapability(struct libztex_device *ztex, int i, int j)
{
	if (!((i >= 0) && (i <= 5) && (j >= 0) && (j < 8) &&
	     (((ztex->interfaceCapabilities[i] & 255) & (1 << j)) != 0))) {
		applog(LOG_ERR, "%s: capability missing: %d %d", ztex->repr, i, j);
		return false;
	}
	return true;
}

static char libztex_detectBitstreamBitOrder(const unsigned char *buf, int size)
//char libztex_detectBitstreamBitOrder(const unsigned char *buf, int size)
{
	int i;

	for (i = 0; i < size - 4; i++) {
		if (((buf[i] & 255) == 0xaa) && ((buf[i + 1] & 255) == 0x99) && ((buf[i + 2] & 255) == 0x55) && ((buf[i + 3] & 255) == 0x66))
			return 1;
		if (((buf[i] & 255) == 0x55) && ((buf[i + 1] & 255) == 0x99) && ((buf[i + 2] & 255) == 0xaa) && ((buf[i + 3] & 255) == 0x66))
			return 0;
	} 
	applog(LOG_ERR, "Unable to determine bitstream bit order: no signature found");
	return 0;
}

//static void libztex_swapBits(unsigned char *buf, int size)
static void libztex_swapBits(unsigned char *buf, int size)
{
	unsigned char c;
	int i;

	for (i = 0; i < size; i++) {
		c = buf[i];
		buf[i] = ((c & 128) >> 7) |
		         ((c & 64) >> 5) |
		         ((c & 32) >> 3) |
		         ((c & 16) >> 1) |
		         ((c & 8) << 1) |
		         ((c & 4) << 3) |
		         ((c & 2) << 5) |
		         ((c & 1) << 7);
	}
}

static bool libztex_getConfigured(struct libztex_device *ztex)
{
	unsigned char buf[9];
	int rc;

	rc = libusb_control_transfer(ztex->hndl, 0xc0, 0x30, 0, 0, buf, 9, 1000);
	if (rc < 0) {
		applog(LOG_ERR, "%s: Unable to get ZTEX Configuration Status (Error: %d)", ztex->repr, rc);
		return false;
	}

	return (buf[0] == 0);
}


bool libztex_configureFpga(struct libztex_device *ztex, const char* bitstream)
{
	const int transactionBytes = 65536;
	unsigned char buf[transactionBytes], settings[2];
	int rc, tries, length, cnt;
	char bs = -1;
	FILE *fp;

	if (!libztex_checkCapability(ztex, CAPABILITY_HS_FPGA)) {
		applog(LOG_ERR, "%s: This ZTEX board does not support HS configuration", ztex->repr);
		return false;
	}

	rc = libusb_control_transfer(ztex->hndl, 0xc0, 0x33, 0, 0, settings, 2, 1000);
	if (rc < 0) {
		applog(LOG_ERR, "%s: Unable to get configuration settings (Error: %d)", ztex->repr, rc);
		return false;
	}

	rc = libusb_claim_interface(ztex->hndl, settings[1]);
	if (rc != LIBUSB_SUCCESS) {
		applog(LOG_ERR, "%s: Unable to claim tnterface for HS transfer (Error: %d)", ztex->repr, rc);
		return false;
	}

	for (tries = 3; tries > 0; tries--) {
		fp = open_bitstream(bitstream);
		if (!fp) {
			applog(LOG_ERR, "%s: Unable to read bitstream '%s'", ztex->repr, bitstream);
			libusb_release_interface(ztex->hndl, settings[1]);
			return false;
		}

		// Initialize HS Configuration
		libusb_control_transfer(ztex->hndl, 0x40, 0x34, 0, 0, NULL, 0, 1000);

		do	{

			length = fread(buf,1,transactionBytes,fp);

			if (bs != 0 && bs != 1)
				bs = libztex_detectBitstreamBitOrder(buf, length);
			if (bs == 1)
				libztex_swapBits(buf, length);

			rc = libusb_bulk_transfer(ztex->hndl, settings[0], buf, length, &cnt, 1000);
			if (cnt != length)
				applog(LOG_ERR, "%s: Only able to send %u of %u bitstream bytes", ztex->repr, cnt, length);
			if (rc != 0)
				applog(LOG_ERR, "%s: Unable to send HS FPGA data", ztex->repr);

		} while (!feof(fp));

		// Finish HS Configuration
		libusb_control_transfer(ztex->hndl, 0x40, 0x35, 0, 0, NULL, 0, 1000);

		if (cnt >= 0)
			tries = 0;

		fclose(fp);

		if (!libztex_getConfigured(ztex)) {
			applog(LOG_ERR, "%s: HS FPGA configuration failed: DONE pin does not go high", ztex->repr);
			libusb_release_interface(ztex->hndl, settings[1]);
			return false;
		}

	}

	libusb_release_interface(ztex->hndl, settings[1]);

	return true;
}

int libztex_numberOfFpgas(struct libztex_device *ztex)
{
	int rc;
	unsigned char buf[3];

	rc = libusb_control_transfer(ztex->hndl, 0xc0, 0x50, 0, 0, buf, 3, 1000);
	if (rc < 0) {
		applog(LOG_ERR, "%s: Unable To Get Number Of FPGAs On ZTEX (Error: %d)", ztex->repr, rc);
		return 0;
	}

	return (rc + 1);
}


bool libztex_selectFpga(struct libztex_device *ztex, int fpgaNum)
{
	int rc;

	if (fpgaNum < 0 || fpgaNum >= ztex->numberOfFpgas) {
		applog(LOG_ERR, "%s: Unable To Select ZTEX FPGA #%d (Only %d Available)", ztex->repr, fpgaNum, ztex->numberOfFpgas - 1);
		return false;
	}
	
	ztex->fpgaNum = fpgaNum;
	rc = libusb_control_transfer(ztex->hndl, 0x40, 0x51, (uint16_t)fpgaNum, 0, NULL, 0, 500);
	if (rc < 0) {
		applog(LOG_ERR, "%s: Unable To Select ZTEX FPGA #%d (Error: %d)", ztex->repr, fpgaNum, rc);
		ztex->selectedFpga = -1;
		return false;
	}

	ztex->selectedFpga = fpgaNum;
	
	return true;
}


bool libztex_setFreq(struct libztex_device *ztex, int freq)
{
	int rc;
	
	if (freq < 0 || freq > 500) {
		applog(LOG_ERR, "%s: Invalid Ztex frequency request (%d)", freq);
		return false;
	}

	rc = libusb_control_transfer(ztex->hndl, 0x40, 0x83, (uint16_t)freq, 0, NULL, 0, 500);
	if (rc < 0) {
		applog(LOG_ERR, "%s-%d: Unable to set frequency (Error: %d)", ztex->repr, ztex->fpgaNum, rc);
		return false;
	}

	applog(LOG_INFO, "%s-%d: Frequency changed to %d", ztex->repr, ztex->fpgaNum, (freq + 1) * 4);

	return true;
}

int libztex_resetFpga(struct libztex_device *ztex)
{
	return libusb_control_transfer(ztex->hndl, 0x40, 0x31, 0, 0, NULL, 0, 1000);
}

int libztex_suspend(struct libztex_device *ztex)
{
	return libusb_control_transfer(ztex->hndl, 0x40, 0x84, 0, 0, NULL, 0, 1000);
}

static int libztex_prepare_device(struct libusb_device *dev, struct libztex_device** ztex)
{
	struct libztex_device *newdev = *ztex;
	int i, cnt, err;
	unsigned char buf[64];

	err = libusb_open(dev, &newdev->hndl);
	if (err != LIBUSB_SUCCESS) {
		applog(LOG_ERR, "%s: Unable to open ZTEX device: %d", __func__, err);
		return CHECK_ERROR;
	}

	err = libusb_get_device_descriptor(dev, &newdev->descriptor);
	if (unlikely(err != 0)) {
		applog(LOG_ERR, "Ztex prepare: Failed to open read descriptor with error %d", err);
		return CHECK_ERROR;
	}

	cnt = libztex_get_string_descriptor_ascii(newdev->hndl, newdev->descriptor.iSerialNumber, newdev->snString, sizeof(newdev->snString));
	if (unlikely(cnt < 0)) {
		applog(LOG_ERR, "Ztex prepare: Failed to read device snString with err %d", cnt);
		return cnt;
	}

	cnt = libusb_control_transfer(newdev->hndl, 0xc0, 0x22, 0, 0, buf, 40, 500);
	if (unlikely(cnt < 0)) {
		applog(LOG_ERR, "Ztex prepare: Failed to read ztex descriptor with err %d", cnt);
		return cnt;
	}

	if (buf[0] != 40 || buf[1] != 1 || buf[2] != 'Z' || buf[3] != 'T' || buf[4] != 'E' || buf[5] != 'X') {
		applog(LOG_ERR, "Ztex prepare: Error reading ztex descriptor");
		return 2;
	}

	newdev->productId[0] = buf[6];
	newdev->productId[1] = buf[7];
	newdev->productId[2] = buf[8];
	newdev->productId[3] = buf[9];
	newdev->fwVersion = buf[10];
	newdev->interfaceVersion = buf[11];
	newdev->interfaceCapabilities[0] = buf[12];
	newdev->interfaceCapabilities[1] = buf[13];
	newdev->interfaceCapabilities[2] = buf[14];
	newdev->interfaceCapabilities[3] = buf[15];
	newdev->interfaceCapabilities[4] = buf[16];
	newdev->interfaceCapabilities[5] = buf[17];
	newdev->moduleReserved[0] = buf[18];
	newdev->moduleReserved[1] = buf[19];
	newdev->moduleReserved[2] = buf[20];
	newdev->moduleReserved[3] = buf[21];
	newdev->moduleReserved[4] = buf[22];
	newdev->moduleReserved[5] = buf[23];
	newdev->moduleReserved[6] = buf[24];
	newdev->moduleReserved[7] = buf[25];
	newdev->moduleReserved[8] = buf[26];
	newdev->moduleReserved[9] = buf[27];
	newdev->moduleReserved[10] = buf[28];
	newdev->moduleReserved[11] = buf[29];

	cnt = libusb_control_transfer(newdev->hndl, 0xc0, 0x82, 0, 0, buf, 64, 500);
	if (unlikely(cnt < 0)) {
		applog(LOG_ERR, "Ztex prepare: Failed to read ztex descriptor with err %d", cnt);
		return cnt;
	}

	newdev->usbbus = libusb_get_bus_number(dev);
	newdev->usbaddress = libusb_get_device_address(dev);
	sprintf(newdev->repr, "ZTEX %s", newdev->snString);
	return 0;
}

void libztex_destroy_device(struct libztex_device* ztex)
{
	if (ztex->hndl != NULL) {
		libusb_close(ztex->hndl);
		ztex->hndl = NULL;
	}
	free(ztex);
}

extern int libztex_scanDevices(struct libztex_dev_list*** devs_p, bool force_firmware)
{
	int usbdevices[LIBZTEX_MAX_DESCRIPTORS];
	struct libztex_dev_list **devs = NULL;
	struct libztex_device *ztex = NULL;
	int found, max_found = 0, pos = 0, err, rescan, ret = 0;
	libusb_device **list = NULL;
	ssize_t cnt, i;

	do {
		cnt = libusb_get_device_list(NULL, &list);
		if (unlikely(cnt < 0)) {
			applog(LOG_ERR, "Ztex scan devices: Failed to list usb devices with err %zd", cnt);
			goto done;
		}

		for (found = rescan = i = 0; i < cnt; i++) {
			err = libztex_checkDevice(list[i], force_firmware);
			switch (err) {
			case CHECK_ERROR:
				applog(LOG_ERR, "Ztex: Unable to check device: %d", err);
				continue;
			case CHECK_IS_NOT_ZTEX:
				continue;
			case CHECK_OK:
				// Got one!
				usbdevices[found++] = i;
				break;
			case CHECK_RESCAN:
				rescan = 1;
				found++;
				break;
			}
		}

		if (found < max_found)
			rescan = 1;
		else if (found > max_found)
			max_found = found;

		if (rescan) {
			libusb_free_device_list(list, 1);
			nmsleep(500);
		}
		
		force_firmware = false;
		
	} while (rescan);

	if (0 == found)
		goto done;

	devs = malloc(sizeof(struct libztex_dev_list *) * found);
	if (devs == NULL) {
		applog(LOG_ERR, "Ztex scan devices: Failed to allocate memory");
		goto done;
	}

	for (i = 0; i < found; i++) {
		if (!ztex) {
			ztex = malloc(sizeof(*ztex));
			if (!ztex) {
				applog(LOG_ERR, "%s: Unable to allocate memory for ZTEX device", __func__);
				goto done;
			}
		}

		err = libztex_prepare_device(list[usbdevices[i]], &ztex);
		if (err != 0) {
			libztex_destroy_device(ztex);
			ztex = NULL;
			continue;
		}

		devs[pos] = malloc(sizeof(struct libztex_dev_list));
		if (NULL == devs[pos]) {
			applog(LOG_ERR, "%s: Unable to allocate memory for ZTEX device", __func__);
			libztex_destroy_device(ztex);
			ztex = NULL;
			continue;
		}

		devs[pos]->dev = ztex;
		ztex = NULL;
		devs[pos]->next = NULL;
		if (pos > 0)
			devs[pos - 1]->next = devs[pos];
		pos++;
	}

	ret = pos;

done:
	if (ret > 0)
		*devs_p = devs;
	else if (devs)
		free(devs);
	if (list)
		libusb_free_device_list(list, 1);
	return ret;
}

int libztex_sendData(struct libztex_device *ztex, unsigned char *sendbuf, int len)
{
	int cnt = 0;
	int idx = 0;

	if (ztex == NULL || ztex->hndl == NULL)
		return 0;

	while (len > 0) {
		cnt = libusb_control_transfer(ztex->hndl, 0x40, 0x80, 0, 0, sendbuf + idx, len, 1000);
		if (cnt >= 0) {
			len -= cnt;
			idx += cnt;
		} else
			break;
	}

	return cnt;
}

int libztex_readData(struct libztex_device *ztex, uint32_t *nonce, uint32_t *hash7, uint32_t *golden)
{
	unsigned char rbuf[16];		// Stores GN1, Nonce, Hash, GN2
	int ret = 16;
	int cnt = 0, len = 0;

	if (ztex->hndl == NULL)
		return 0;

	while (ret > 0) {
		cnt = libusb_control_transfer(ztex->hndl, 0xc0, 0x81, 0, 0, rbuf + len, ret, 1000);
		if (cnt >= 0) {
			ret -= cnt;
			len += cnt;
		} else
			break;
	}

	if (unlikely(cnt < 0)) {
		applog(LOG_ERR, "%s: Unable To Read ZTEX (Error: %d)", ztex->repr, cnt);
		return cnt;
	}
	
	memcpy((unsigned char*)&golden[0], &rbuf[0], 4);
	memcpy((unsigned char*)nonce,      &rbuf[4], 4);
	memcpy((unsigned char*)hash7,      &rbuf[8], 4);
	memcpy((unsigned char*)&golden[1], &rbuf[12], 4);
	
	return cnt;
}


void libztex_freeDevList(struct libztex_dev_list **devs)
{
	bool done = false;
	ssize_t cnt = 0;

	while (!done) {
		if (devs[cnt]->next == NULL)
			done = true;
		free(devs[cnt++]);
	}
	free(devs);
}

