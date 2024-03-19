/*
 * mi_ufsswap.h
 *
 * Created on: 2023-06-01
 *
 * Authors:
 *	lijiaming <lijiaming3@xiaomi.com>
 */

#ifndef _UFSSWAP_H_
#define _UFSSWAP_H_

#include <linux/sysfs.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/scsi_device.h>
#include <linux/types.h>
#include <asm/unaligned.h>

#define QUERY_DESC_OFFSET_SWAP_MAX_BUF_SIZE_SAMSUNG	0xE7
#define QUERY_DESC_OFFSET_SWAP_MIN_BUF_SIZE_SAMSUNG	0xEB
#define QUERY_ATTR_IDN_SWAP_MAX_BUF_SIZE_HYNIX    	0x80
#define QUERY_ATTR_IDN_SWAP_MIN_BUF_SIZE_HYNIX		0x81
#define QUERY_ATTR_IDN_SWAP_AVAIL_BUF_SIZE_HYNIX   	0x82
#define QUERY_ATTR_IDN_SWAP_TOTAL_WRITE_COUNT_HYNIX   	0x83

#define QUERY_ATTR_IDN_SWAP_MAX_BUF_SIZE_MICRON    	0x84
#define QUERY_ATTR_IDN_SWAP_MIN_BUF_SIZE_MICRON		0x85
#define QUERY_ATTR_IDN_SWAP_AVAIL_BUF_SIZE_MICRON    	0x86
#define QUERY_ATTR_IDN_SWAP_TOTAL_WRITE_COUNT_MICRON    0x87
#define QUERY_ATTR_IDN_SWAP_NEED_ENABLE_PIN_BUF_SAMSUNG	0x93

#define QUERY_DESC_IDN_SWAP_MAX_BUF_SIZE_SAMSUNG	0xF0
#define QUERY_ATTR_IDN_SWAP_MAX_BUF_SIZE_SAMSUNG	0x9A
#define QUERY_ATTR_IDN_SWAP_MIN_BUF_SIZE_SAMSUNG	0x9B
#define QUERY_ATTR_IDN_SWAP_AVAIL_BUF_SIZE_SAMSUNG    	0x95
#define QUERY_ATTR_IDN_SWAP_TOTAL_WRITE_COUNT_SAMSUNG   0x96

#define QUERY_ATTR_IDN_SWAP_MAX_BUF_SIZE_KIOXIA 	0x80
#define QUERY_ATTR_IDN_SWAP_MIN_BUF_SIZE_KIOXIA		0x81
#define QUERY_ATTR_IDN_SWAP_AVAIL_BUF_SIZE_KIOXIA 	0x42
#define QUERY_ATTR_IDN_SWAP_TOTAL_WRITE_COUNT_KIOXIA 	0x43
#define QUERY_ATTR_IDN_SWAP_NEED_ENABLE_PIN_BUF_KIOXIA 	0x3F

#define SWAP_WRITE_GROUP_NUM    			0x18
#define SWAP_READ_GROUP_NUM    				0x18
#define UFSSWAP_EBABLE

#define SWAP_SLC_3GB  0x300
#define SWAP_SLC_5GB  0x500
#define SWAP_SLC_7GB  0x700
#define SWAP_SLC_10GB  0xa00
#define SWAP_WB_MIN_2GB  0x200
#define NON_PINNED_BUF_10GB 0xa00

enum UFSSWAP_STATE {
	SWAP_NEED_INIT = 0,
	SWAP_PRESENT = 1,
	SWAP_FAILED = -2,
	SWAP_RESET = -3,
};

struct ufsswap_dev_spec {
	u8 idn_max_buf_size;
	u8 idn_min_buf_size;
	u8 idn_avail_buf_size;
	u8 idn_total_write_cnt;
	u8 offset_max_buf_size;
	u8 idn_need_enable_pin_buf;
	u8 val_enable_pin_buf;
	u8 gr_write;
	u8 gr_read;
};

struct ufsswap_dev_info {
	u32 swap_max_buf_size;
	u32 swap_min_buf_size;
	u32 swap_file_lba_count;
	u32 density;
	struct ufsswap_dev_spec *swap_dev_spec;
};

struct ufsswap_lba_info {
	struct list_head list;
	u32 lba_pre;
	u32 lba_post;
};

struct ufsswap_ctrl {
	struct ufs_hba *hba;
	struct ufsswap_dev_info swap_dev_info;
	atomic_t swap_state;
	u8 swap_enable;
	struct list_head lba_list_head;
	/* for sysfs */
	struct kobject kobj;
	struct mutex sysfs_lock;
	struct ufsswap_sysfs_entry *sysfs_entries;
};

struct ufsswap_sysfs_entry {
	struct attribute attr;
	ssize_t (*show)(struct ufsswap_ctrl *swap_ctrl, char *buf);
	ssize_t (*store)(struct ufsswap_ctrl *swap_ctrl, const char *buf, size_t count);
};

struct ufsswap_standard_inquiry {
	uint8_t vendor_id[8];
	uint8_t product_id[16];
	uint8_t product_rev[4];
};

int ufsswap_probe(struct ufs_hba *hba);
void ufsswap_remove(struct ufs_hba *hba);

#endif /* _UFSSWAP_H_ */
