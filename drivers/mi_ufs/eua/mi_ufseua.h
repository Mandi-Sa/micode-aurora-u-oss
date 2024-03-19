/*
 * ufseua.h
 *
 * Created on: 2023-05-30
 *
 * Authors:
 *	lijiaming <lijiaming3@xiaomi.com>
 */

#ifndef _UFSEUA_H_
#define _UFSEUA_H_

#include <linux/sysfs.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_common.h>
#include <linux/types.h>
#include <asm/unaligned.h>
#include <linux/blkdev.h>
#include "../../misc/hwid/hwid.h"

struct ufseua_ctrl {
	struct ufs_hba *hba;
	struct ufseua_ops *ops;
	struct scsi_device *sdev_ufs_lu;
	u8 support;
	u16 lba_length;
	u64 lba_pre;
	u64 lba_post;
	int density;
	/* for sysfs */
	struct kobject kobj;
	struct mutex sysfs_lock;
	struct ufseua_sysfs_entry *sysfs_entries;
};

struct ufseua_ops {
	int (*eua_get_mapping_status)(struct ufseua_ctrl *eua_ctrl, char *lba_info);
	int (*eua_get_total_used_lba)(struct ufseua_ctrl *eua_ctrl, u32 *val);
	int (*eua_get_free_space)(struct ufseua_ctrl *eua_ctrl, u32 *val);
};

struct ufseua_sysfs_entry {
	struct attribute attr;
	ssize_t (*show)(struct ufseua_ctrl *eua_ctrl, char *buf);
	ssize_t (*store)(struct ufseua_ctrl *eua_ctrl, const char *buf, size_t count);
};

struct ufseua_standard_inquiry {
	uint8_t vendor_id[8];
	uint8_t product_id[16];
	uint8_t product_rev[4];
};

int ufseua_probe(struct ufs_hba *hba);
void ufseua_remove(struct ufs_hba *hba);

#endif /* _UFSEUA_H_ */
