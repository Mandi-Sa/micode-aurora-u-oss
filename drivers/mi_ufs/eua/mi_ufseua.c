/*
 * ufseua.c
 *
 * Created on: 2023-05-30
 *
 * Authors:
 *	lijiaming <lijiaming3@xiaomi.com>
 */
#include <linux/pm_runtime.h>
#include "mi_ufseua.h"
#include "../include/ufshcd.h"
#include "../include/ufs.h"
#include "../../ufs/host/ufs-qcom.h"
#include "../core/ufshcd-priv.h"
#include <linux/mutex.h>

static DEFINE_MUTEX(hr_lock);
#define MAX_MAPPING_BUF_SIZE 512
#define KIOXIA_TOTAL_USED_LBA_OFFSET 176
#define KIOXIA_TOTAL_FREE_SPACE_OFFSET 184
#define UNMAP_PARAM_SIZE	24
#define EUA_CAP_PRE_256 0x1EC7C000// 0x1ECBC000-0x40000
#define EUA_CAP_POST_256 0x1ECFC000// 0x1ECBC000+0x40000
#define EUA_CAP_PRE_512 0x3D92C000// 0x3D96C000-0x40000
#define EUA_CAP_POST_512 0x3D9AC000// 0x3D96C000+0x40000
#define EUA_CAP_PRE_1024 0x7B298000// 0x7B2D8000-0x40000
#define EUA_CAP_POST_1024 0x7B318000// 0x7B2D8000+0x40000

#define HWID_BUILD_VERSION_P0 0
#define HWID_BUILD_VERSION_P1 1
#define HWID_BUILD_VERSION_P2 2
#define HWID_BUILD_VERSION_MP 9

static int ufseua_read_desc(struct ufs_hba *hba, u8 desc_id, u8 desc_index,
			u8 selector, u8 *desc_buf, u32 size)
{
	int ret = 0;
	int retries;
	ufshcd_rpm_get_sync(hba);

	for (retries = 3; retries > 0; retries--) {
		ret = __ufshcd_query_descriptor(hba, UPIU_QUERY_OPCODE_READ_DESC,
					    desc_id, desc_index,
					    selector,
					    desc_buf, &size);
		if (!ret || ret == -EINVAL)
			break;
        }

	if (ret)
		pr_err("[UFSEUA]Read desc [0x%.2X] failed. (%d)", desc_id, ret);

	ufshcd_rpm_put_sync(hba);

	return ret;
}

static int eua_scsi_execute(struct scsi_device *sdev, const unsigned char *cmd,
		     blk_opf_t opf, void *buffer, unsigned int bufflen,
		     int timeout, int retries,
		     const struct scsi_exec_args *args)
{
	static const struct scsi_exec_args default_args;
	struct request *req;
	struct scsi_cmnd *scmd;
	int ret;

	if (!args)
		args = &default_args;
	else if (WARN_ON_ONCE(args->sense &&
			      args->sense_len != SCSI_SENSE_BUFFERSIZE))
		return -EINVAL;

	req = scsi_alloc_request(sdev->request_queue, opf, args->req_flags);
	if (IS_ERR(req))
		return PTR_ERR(req);

	if (bufflen) {
		ret = blk_rq_map_kern(sdev->request_queue, req,
				      buffer, bufflen, GFP_NOIO);
		if (ret)
			goto out;
	}
	scmd = blk_mq_rq_to_pdu(req);
	scmd->cmd_len = COMMAND_SIZE(cmd[0]);
	if (cmd[0] == 0xC0 || cmd[0] == 0xD0)
		scmd->cmd_len = 16;
	if (cmd[0] == WRITE_BUFFER || cmd[0] == READ_BUFFER)
		scmd->cmd_len = 16;
	memcpy(scmd->cmnd, cmd, scmd->cmd_len);
	scmd->allowed = retries;
	scmd->flags |= args->scmd_flags;
	req->timeout = timeout;
	req->rq_flags |= RQF_QUIET;

	/*
	 * head injection *required* here otherwise quiesce won't work
	 */
	blk_execute_rq(req, true);

	/*
	 * Some devices (USB mass-storage in particular) may transfer
	 * garbage data together with a residue indicating that the data
	 * is invalid.  Prevent the garbage from being misinterpreted
	 * and prevent security leaks by zeroing out the excess data.
	 */
	if (unlikely(scmd->resid_len > 0 && scmd->resid_len <= bufflen))
		memset(buffer + bufflen - scmd->resid_len, 0, scmd->resid_len);

	if (args->resid)
		*args->resid = scmd->resid_len;
	if (args->sense)
		memcpy(args->sense, scmd->sense_buffer, SCSI_SENSE_BUFFERSIZE);
	if (args->sshdr)
		scsi_normalize_sense(scmd->sense_buffer, scmd->sense_len,
				     args->sshdr);

	ret = scmd->result;
out:
	blk_mq_free_request(req);

	return ret;
}

static int hynix_eua_get_mapping_status(struct ufseua_ctrl *eua_ctrl,
								char *lba_mapping_info)
{
	int ret = 0;
	uint8_t cdb[16];
	unsigned long flags = 0;
	struct ufs_hba *hba = eua_ctrl->hba;
	struct scsi_device *sdev = eua_ctrl->sdev_ufs_lu;
	struct scsi_sense_hdr sshdr = {};
	const struct scsi_exec_args exec_args = {
		.sshdr = &sshdr,
		.req_flags = BLK_MQ_REQ_PM,
	};

	ufshcd_rpm_get_sync(hba);
	ufshcd_hold(hba, false);

	spin_lock_irqsave(hba->host->host_lock, flags);
	ret = scsi_device_get(sdev);
	if (!ret && !scsi_device_online(sdev)) {
		ret = -ENODEV;
		scsi_device_put(sdev);
	}
	spin_unlock_irqrestore(hba->host->host_lock, flags);

	if (ret){
		pr_err("[UFSEUA]Get device fail");
		goto out;
	}

	cdb[0] = READ_BUFFER;
	cdb[1] = 0x01;
	cdb[2] = 0x07;
	put_unaligned_be24(eua_ctrl->lba_length, cdb + 6);
	put_unaligned_be32(eua_ctrl->lba_pre, cdb + 10);
	put_unaligned_be16(eua_ctrl->lba_length, cdb + 14);

	ret = eua_scsi_execute(sdev, cdb, REQ_OP_DRV_IN, lba_mapping_info,
				  eua_ctrl->lba_length, msecs_to_jiffies(15000), 0, &exec_args);

	if (ret)
		pr_err("[UFSEUA]Read Buffer failed,sense key:0x%x;asc:0x%x;ascq:0x%x",
					(int)sshdr.sense_key, (int)sshdr.asc, (int)sshdr.ascq);
	scsi_device_put(sdev);

out:
	ufshcd_release(hba);
	ufshcd_rpm_put_sync(hba);

	return ret;
}

static int hynix_eua_get_total_used_lba(struct ufseua_ctrl *eua_ctrl,
									u32 *val)
{
	int ret = 0;
	uint8_t cdb[16];
	unsigned long flags = 0;
	struct ufs_hba *hba = eua_ctrl->hba;
	struct scsi_sense_hdr sshdr = {};
	const struct scsi_exec_args exec_args = {
		.sshdr = &sshdr,
		.req_flags = BLK_MQ_REQ_PM,
	};
	struct scsi_device *sdev = eua_ctrl->sdev_ufs_lu;

	ufshcd_rpm_get_sync(hba);
	ufshcd_hold(hba, false);

	spin_lock_irqsave(hba->host->host_lock, flags);
	ret = scsi_device_get(sdev);
	if (!ret && !scsi_device_online(sdev)) {
		ret = -ENODEV;
		scsi_device_put(sdev);
	}
	spin_unlock_irqrestore(hba->host->host_lock, flags);

	if (ret){
		pr_err("[UFSEUA]Get device fail");
		goto out;
	}

	cdb[0] = READ_BUFFER;
	cdb[1] = 0x01;
	cdb[2] = 0x08;

	put_unaligned_be24(4, cdb + 6);

	ret = eua_scsi_execute(sdev, cdb, REQ_OP_DRV_IN, val,
				4, msecs_to_jiffies(15000), 0, &exec_args);
	if (ret)
		pr_err("[UFSEUA]Read Buffer failed,sense key:0x%x;asc:0x%x;ascq:0x%x",
					(int)sshdr.sense_key, (int)sshdr.asc, (int)sshdr.ascq);

	scsi_device_put(sdev);

out:
	ufshcd_release(hba);
	ufshcd_rpm_put_sync(hba);

	return ret;
}

static int eua_get_sk_hr(struct scsi_device *sdev, struct ufs_hba *hba,
				char *buf, int len)
{
	int ret;
	struct scsi_sense_hdr sshdr = {};
	const struct scsi_exec_args exec_args = {
		.sshdr = &sshdr,
		.req_flags = BLK_MQ_REQ_PM,
	};
	unsigned char cdb[16] = {0};

	if (!buf)
		return -EINVAL;

	cdb[0] = 0xD0; /*VENDOR_SPECIFIC_CDB;*/
	cdb[1] = 0x0F;
	cdb[2] = 0x53;
	cdb[11] = 0x6F;

	ret = eua_scsi_execute(sdev, cdb, REQ_OP_DRV_IN, buf,
				  len, 30 * HZ, 0, &exec_args);
	if (ret) {
		pr_err("[UFSEUA]get skhynix ret error 0x%x\n", ret);
		return -EIO;
	}

	return 0;
}

static int hynix_eua_get_free_space(struct ufseua_ctrl *eua_ctrl,
									u32 *val)
{
	struct ufs_hba *hba = eua_ctrl->hba;
	struct scsi_device *sdev = eua_ctrl->sdev_ufs_lu;
	char *hr;
	char *seg;
	int ret = 0;
	unsigned long flags = 0;

	hr =  kzalloc(512, GFP_KERNEL);
	if (!hr) {
		pr_err("[UFSEUA]kzalloc fail\n");
		return -ENOMEM;
	}
	mutex_lock(&hr_lock);

	seg = hr + 0x80;

	spin_lock_irqsave(hba->host->host_lock, flags);
	ret = scsi_device_get(sdev);
	if (!ret && !scsi_device_online(sdev)) {
		ret = -ENODEV;
		scsi_device_put(sdev);
		pr_info("[UFSEUA]get device fail\n");
	}
	spin_unlock_irqrestore(hba->host->host_lock, flags);

	if (ret)
		goto out_unlock;

	hba->host->eh_noresume = 1;

	ret = ufseua_read_desc(hba, QUERY_DESC_IDN_HEALTH, 0, 0,
			hr, QUERY_DESC_HEALTH_DEF_SIZE);
	if(ret)
		goto out;

	ret = eua_get_sk_hr(sdev, hba, seg, 0x6F);
	if(ret)
		goto out;
	/* 0x80 + 0x6E(offset of freespace needed by eua) */
	*val = hr[238];

out:
	scsi_device_put(sdev);
	hba->host->eh_noresume = 0;
out_unlock:
	mutex_unlock(&hr_lock);
	kfree(hr);
	return ret;
}

static int kioxia_inquiry(struct ufs_hba *hba, struct scsi_device *sdev, char *buf)
{
	int ret = 0;
	unsigned long flags = 0;
	unsigned char cdb[16] = {0};
	struct scsi_sense_hdr sshdr = {};
	const struct scsi_exec_args exec_args = {
		.sshdr = &sshdr,
		.req_flags = BLK_MQ_REQ_PM,
	};

	if (!buf)
		return -EINVAL;

	spin_lock_irqsave(hba->host->host_lock, flags);
	ret = scsi_device_get(sdev);
	if (!ret && !scsi_device_online(sdev)) {
		ret = -ENODEV;
		scsi_device_put(sdev);
		pr_info("[UFSEUA]get device fail\n");
	}
	spin_unlock_irqrestore(hba->host->host_lock, flags);

	if (ret)
		return ret;

	hba->host->eh_noresume = 1;

	cdb[0] = INQUIRY;
	cdb[1] = 0x69;		/* EVPD */
	cdb[2] = 0xC0;
	put_unaligned_be16(0x200, cdb + 3);
	cdb[5] = 0;		/* Control byte */

	ret = eua_scsi_execute(sdev, cdb, REQ_OP_DRV_IN, buf,
				  0x200, 30 * HZ, 0, &exec_args);
	if (ret)
		pr_err("[UFSEUA]get kioxia ret error 0x%x\n", ret);

	scsi_device_put(sdev);
	hba->host->eh_noresume = 0;

	return ret;
}

static int micron_eua_get_mapping_status(struct ufseua_ctrl *eua_ctrl,
								char *lba_mapping_info)
{
	return 0;
}

static int micron_eua_get_total_used_lba(struct ufseua_ctrl *eua_ctrl,
									u32 *val)
{
	return 0;
}

static int micron_eua_get_free_space(struct ufseua_ctrl *eua_ctrl,
									u32 *val)
{
	return 0;
}

static int kioxia_eua_get_total_used_lba(struct ufseua_ctrl *eua_ctrl,
									u32 *val)
{
	int ret = 0;
	char *buf;
	struct ufs_hba *hba = eua_ctrl->hba;
	struct scsi_device *sdev = eua_ctrl->sdev_ufs_lu;

	buf =  kzalloc(512, GFP_KERNEL);
	if (!buf) {
		pr_err("[UFSEUA]kzalloc fail\n");
		return -ENOMEM;
	}

	mutex_lock(&hr_lock);
	ret = kioxia_inquiry(hba, sdev, buf);

	if (ret) {
		pr_err("[UFSEUA]get kioxia eua hr failed 0x%x\n", ret);
		goto out;
	}
	*val = get_unaligned_be32(buf + KIOXIA_TOTAL_USED_LBA_OFFSET);

out:
	mutex_unlock(&hr_lock);
	kfree(buf);
	return ret;
}

static int kioxia_eua_get_free_space(struct ufseua_ctrl *eua_ctrl,
									u32 *val)
{
	int ret = 0;
	char *buf;
	u64 tmp = 0;
	struct ufs_hba *hba = eua_ctrl->hba;
	struct scsi_device *sdev = eua_ctrl->sdev_ufs_lu;

	buf =  kzalloc(512, GFP_KERNEL);
	if (!buf) {
		pr_err("[UFSEUA]kzalloc fail\n");
		return -ENOMEM;
	}

	mutex_lock(&hr_lock);
	ret = kioxia_inquiry(hba, sdev, buf);

	if (ret) {
		pr_err("[UFSEUA]get kioxia eua hr failed 0x%x\n", ret);
		goto out;
	}
	tmp = get_unaligned_be32(buf + KIOXIA_TOTAL_FREE_SPACE_OFFSET);
	tmp = tmp * 4 * 100 / (1024 * 1024 * eua_ctrl->density);
	*val = tmp;

out:
	mutex_unlock(&hr_lock);
	kfree(buf);
	return ret;
}

struct eua_policy_checklist {
	uint8_t vendor_id[9];
	uint8_t product_id[17];
	uint8_t product_rev[5];
	int density;
	struct ufseua_ops *eua_ops;
};

struct ufseua_ops hynix_eua_ops = {
	.eua_get_mapping_status = hynix_eua_get_mapping_status,
	.eua_get_total_used_lba = hynix_eua_get_total_used_lba,
	.eua_get_free_space = hynix_eua_get_free_space
};

struct ufseua_ops micron_eua_ops = {
	.eua_get_mapping_status = micron_eua_get_mapping_status,
	.eua_get_total_used_lba = micron_eua_get_total_used_lba,
	.eua_get_free_space = micron_eua_get_free_space
};

struct ufseua_ops kioxia_eua_ops = {
	.eua_get_total_used_lba = kioxia_eua_get_total_used_lba,
	.eua_get_free_space = kioxia_eua_get_free_space
};

static struct eua_policy_checklist policy[] = {
	{"SKhynix", "HN8T174EJKX075", "X202", 264, &hynix_eua_ops},
	{"SKhynix", "HN8T274EJKX130", "X202", 528, &hynix_eua_ops},
	{"KIOXIA", "THGJFLT2E46BATPB", "", 528, &kioxia_eua_ops},
	{"MICRON", "MT256GBEAX4U40", "", 264, &micron_eua_ops},
	{"MICRON", "MT512GAYAX4U40", "", 528, &micron_eua_ops},
	{"MICRON", "MT001TAYAX8U40", "", 1056, &micron_eua_ops},
};

#if defined(CONFIG_FACTORY_BUILD) && defined(CONFIG_UFS_EUA_CHECK)
static void ufseua_check_fail(void)
{
	/*
		This function is only used to block machines that do
		not have Ultra Space in factory
	*/
	int project_build_version = -1;

	project_build_version = get_hw_version_build();
	pr_err("[UFSEUA]hardware build version %d\n", project_build_version);
	if (project_build_version == HWID_BUILD_VERSION_MP) {
		pr_err("[UFSEUA]not eua machines, please contact BSP-Memory\n");
		dump_stack();
		BUG_ON(1);
	}

	pr_err("[UFSEUA]not eua machines, but build version is not MP(9)\n");
}
#else
static void ufseua_check_fail(void)
{
	pr_info("[UFSEUA]not factory or no need for check\n");
	return;
}
#endif

static int check_eua_policy(struct ufs_hba *hba)
{
	int i = 0;
	struct ufseua_standard_inquiry stdinq = {};
	struct ufseua_ctrl *eua_ctrl = &hba->eua_ctrl;

	if(!hba->ufs_device_wlun){
		ERR_MSG("ufs_device_wlun init fail, maybe UFS had issues before this.");
		return -EOPNOTSUPP;
	}

	memcpy(&stdinq, hba->ufs_device_wlun->inquiry + 8, sizeof(stdinq));

	for (i = 0; i < sizeof(policy)/sizeof(policy[0]); i++) {
		if (!strncmp((char *)stdinq.vendor_id, (char *)policy[i].vendor_id, strlen((char *)policy[i].vendor_id))
			&& !strncmp((char *)stdinq.product_id, (char *)policy[i].product_id, strlen((char *)policy[i].product_id))) {
			if (strlen((char *)policy[i].product_rev)) {
				if (strncmp((char *)stdinq.product_rev, (char *)policy[i].product_rev, strlen((char *)policy[i].product_rev))) {
					/*Has FW rev, but not match*/
					pr_err("[UFSEUA]Firmware rev check fail\n");
					ufseua_check_fail();
					return -EOPNOTSUPP;
				}
			}
			eua_ctrl->ops = policy[i].eua_ops;
			eua_ctrl->density = policy[i].density;
			pr_info("[UFSEUA]policy match[%d]", i + 1);
			return 0;
		}
	}

	return -EOPNOTSUPP;
}

/*
   Total memory quantity available to the user to configure
   the device logical units (RPMB excluded).It is expressed
   in unit of 512 bytes
*/
static int check_eua_total_raw_cap(struct ufs_hba *hba)
{
	u8 *desc_buf;
	u64 val = 0;
	int ret = 0;

	desc_buf =  kzalloc(QUERY_DESC_MAX_SIZE, GFP_KERNEL);
	if (!desc_buf) {
		pr_err("[UFSEUA]kzalloc fail\n");
		return -ENOMEM;
	}

	ret = ufseua_read_desc(hba, QUERY_DESC_IDN_GEOMETRY,
				0, 0, desc_buf, QUERY_DESC_MAX_SIZE);
	if (ret) {
		ret = -EOPNOTSUPP;
		goto out;
	}

	val = get_unaligned_be64(desc_buf + GEOMETRY_DESC_PARAM_DEV_CAP);
	pr_info("[UFSEUA]raw device capacity:0x%x", val);

	if ((EUA_CAP_PRE_256 < val && val < EUA_CAP_POST_256)
		|| (EUA_CAP_PRE_512 < val && val < EUA_CAP_POST_512)
		|| (EUA_CAP_PRE_1024 < val && val < EUA_CAP_POST_1024))
		goto out;

	ret = -EOPNOTSUPP;
out:
	kfree(desc_buf);
	return ret;
}

/* Wrapper functions for safely calling variant operations */
static int ufseua_get_mapping_status(struct ufseua_ctrl *eua_ctrl,
									char *read_buf)
{
	if (eua_ctrl->ops && eua_ctrl->ops->eua_get_mapping_status)
		return eua_ctrl->ops->eua_get_mapping_status(eua_ctrl, read_buf);

	return -ENOTSUPP;
}

static int ufseua_get_total_used_lba(struct ufseua_ctrl *eua_ctrl,
									u32 *val)
{
	if (eua_ctrl->ops && eua_ctrl->ops->eua_get_total_used_lba)
		return eua_ctrl->ops->eua_get_total_used_lba(eua_ctrl, val);

	return -ENOTSUPP;
}

static int ufseua_get_total_free_space(struct ufseua_ctrl *eua_ctrl,
									u32 *val)
{
	if (eua_ctrl->ops && eua_ctrl->ops->eua_get_free_space)
		return eua_ctrl->ops->eua_get_free_space(eua_ctrl, val);

	return -ENOTSUPP;
}

static int ufseua_get_lba_info(struct ufseua_ctrl *eua_ctrl,
						      const char *buf)
{
	int i = 0;
	int ret = 0;
	char *buf_ptr;
	char *lba_tmp;
	u64 lba_value_tmp;
	int len_index = 1;

	buf_ptr = kstrdup(buf, GFP_KERNEL);
	if (unlikely(!buf_ptr))
		return -ENOMEM;
	
	while((lba_tmp = strsep(&buf_ptr, ",")) != NULL) {
		if (i > 1)
			break;
		ret = kstrtou64(lba_tmp, 16, &lba_value_tmp);
		if (ret) {
			ret = -EINVAL;
			goto out;
		}

		if (len_index % 2)
			eua_ctrl->lba_pre = lba_value_tmp;
		else {
			if (lba_value_tmp < eua_ctrl->lba_pre){
				ret = -EINVAL;
				goto out;
			}
			eua_ctrl->lba_post = lba_value_tmp;
			i++;
		}
		len_index++;
	}

	eua_ctrl->lba_length = eua_ctrl->lba_post - eua_ctrl->lba_pre + 1;

out:
	kfree(buf_ptr);
	return ret;
}

static int ufseua_parser_unmap_info(struct ufseua_ctrl *eua_ctrl, const char *buf)
{
	struct ufs_hba *hba = eua_ctrl->hba;
	struct scsi_device *sdev = eua_ctrl->sdev_ufs_lu;
	struct scsi_sense_hdr sshdr = {};
	const struct scsi_exec_args exec_args = {
		.sshdr = &sshdr,
		.req_flags = BLK_MQ_REQ_PM,
	};
	char *buf_ptr;
	char *buf_ptr_org; /* record buf_ptr after kstrdup */
	unsigned char cdb[10] = {0};
	u8 param[UNMAP_PARAM_SIZE] = {0};
	int ret = 0;
	char *lba_tmp;
	u64 val_tmp;
	u64 lba;
	u32 blocks;
	int index = 1;
	unsigned long flags = 0;

	spin_lock_irqsave(hba->host->host_lock, flags);
	ret = scsi_device_get(sdev);
	if (!ret && !scsi_device_online(sdev)) {
		ret = -ENODEV;
		scsi_device_put(sdev);
	}
	spin_unlock_irqrestore(hba->host->host_lock, flags);

	//parser buf_ptr
	buf_ptr = kstrdup(buf, GFP_KERNEL);
	if (unlikely(!buf_ptr))
		return -ENOMEM;
	buf_ptr_org =  buf_ptr;

	while((lba_tmp = strsep(&buf_ptr_org, ",")) != NULL) {
		ret = kstrtou64(lba_tmp, 16, &val_tmp);

		if (index % 2) {
			lba = val_tmp;
		} else {
			blocks = val_tmp - lba + 1;
		}
		index++;
	}
	pr_info("[UFSEUA]unmap lba:0x%x,length:%d", lba, blocks);

	param[1] = 22;                      // n - 1
	param[3] = 16;                      // n - 7

	param[12] = (lba >> 24) & 0xff;     // Lower 32 bits of LBA
	param[13] = (lba >> 16) & 0xff;
	param[14] = (lba >> 8) & 0xff;
	param[15] = (lba) & 0xff;
	param[16] = (blocks >> 24) & 0xff;  // Blocks
	param[17] = (blocks >> 16) & 0xff;
	param[18] = (blocks >> 8) & 0xff;
	param[19] = (blocks) & 0xff;

	cdb[0] = UNMAP;
	cdb[8] = UNMAP_PARAM_SIZE;

	ret = eua_scsi_execute(sdev, cdb, REQ_OP_DRV_OUT, param,
			UNMAP_PARAM_SIZE, 30 * HZ, 0, &exec_args);
	if (ret)
		pr_err("[UFSEUA]UNMAP failed,sense key:0x%x;asc:0x%x;ascq:0x%x",
			(int)sshdr.sense_key, (int)sshdr.asc, (int)sshdr.ascq);

	scsi_device_put(sdev);
	kfree(buf_ptr);
	return ret;
}

static ssize_t ufseua_sysfs_store_eua_get_mapping_status(struct ufseua_ctrl *eua_ctrl,
						      const char *buf,
						      size_t count)
{
	int ret = 0;

	ret = ufseua_get_lba_info(eua_ctrl, buf);
	if (ret) {
		pr_err("[UFSEUA]Get lba range level failed");
		goto out;
	}

	pr_info("[UFSEUA]pre[0x%x],post[0x%x]\n",eua_ctrl->lba_pre,eua_ctrl->lba_post);

out:
	return count;
}

static ssize_t ufseua_sysfs_show_eua_get_mapping_status(struct ufseua_ctrl *eua_ctrl,
													char *buf)
{
	int i, ret, count = 0;
	char *eua_read_buf;
	int active_length = 0;

	eua_read_buf = kzalloc(MAX_MAPPING_BUF_SIZE, GFP_KERNEL);//max 2MB
	if (!eua_read_buf) {
		ret = -ENOMEM;
		return ret;
	}

	if (eua_ctrl->lba_length > MAX_MAPPING_BUF_SIZE)
		eua_ctrl->lba_length = MAX_MAPPING_BUF_SIZE;

	active_length = (eua_ctrl->lba_length + 7) / 8;

	ret = ufseua_get_mapping_status(eua_ctrl, eua_read_buf);
	if (ret) {
		pr_err("[UFSEUA]Get mapping status failed");
		goto out;
	}

	for(i = 0; i < active_length; i++) {
		count += snprintf(buf + count, PAGE_SIZE - count, "%02x", eua_read_buf[i]);
	}
	count += snprintf(buf + count, PAGE_SIZE - count, "\n");

out:
	kfree(eua_read_buf);
	return count;
}

static ssize_t ufseua_sysfs_show_eua_get_total_free_space(struct ufseua_ctrl *eua_ctrl,
													char *buf)
{
	int ret;
	u32 val = 0;

	ret = ufseua_get_total_free_space(eua_ctrl, &val);
	if (ret) {
		pr_err("[UFSEUA]Get total free space failed");
		return -EINVAL;
	}

	return sysfs_emit(buf, "%d\n", val);
}

static ssize_t ufseua_sysfs_show_eua_get_total_used_lba(struct ufseua_ctrl *eua_ctrl,
													char *buf)
{
	int ret;
	u32 val = 0;

	ret = ufseua_get_total_used_lba(eua_ctrl, &val);
	if (ret) {
		pr_err("[UFSEUA]Get total used lba failed");
		return -EINVAL;
	}

	return sysfs_emit(buf, "%d\n", val);
}

static ssize_t ufseua_sysfs_store_eua_file_lba_unmap(struct ufseua_ctrl *eua_ctrl,
						      const char *buf,
						      size_t count)
{
	int ret = 0;

	ret = ufseua_parser_unmap_info(eua_ctrl, buf);
	if (ret) {
		pr_err("[UFSEUA]unmap lba range failed");
		return -EINVAL;
	}

	pr_info("[UFSEUA]unmap lba range success");
	return count;
}

static ssize_t ufseua_sysfs_show_eua_support(struct ufseua_ctrl *eua_ctrl,
													char *buf)
{
	return sysfs_emit(buf, "%d\n", eua_ctrl->support);
}

static ssize_t ufseua_sysfs_show_eua_support_size(struct ufseua_ctrl *eua_ctrl,
													char *buf)
{
	int density = 0;

	switch(eua_ctrl->density){
	case 264:
		density = 8;
		break;
	case 528:
		density = 16;
		break;
	case 1056:
		density = 32;
		break;
	default:
		break;
	}

	return sysfs_emit(buf, "%d\n", density);
}

#define define_sysfs_ro(_name) __ATTR(_name, 0444,			\
				      ufseua_sysfs_show_##_name, NULL)
#define define_sysfs_wo(_name) __ATTR(_name, 0200,			\
				       NULL, ufseua_sysfs_store_##_name)
#define define_sysfs_rw(_name) __ATTR(_name, 0644,			\
				      ufseua_sysfs_show_##_name,	\
				      ufseua_sysfs_store_##_name)

static struct ufseua_sysfs_entry ufseua_sysfs_entries[] = {
	define_sysfs_ro(eua_get_total_free_space),
	define_sysfs_ro(eua_get_total_used_lba),
	define_sysfs_ro(eua_support),
	define_sysfs_ro(eua_support_size),
	define_sysfs_rw(eua_get_mapping_status),
	define_sysfs_wo(eua_file_lba_unmap),
	__ATTR_NULL
};

static ssize_t ufseua_attr_show(struct kobject *kobj, struct attribute *attr,
				char *page)
{
	struct ufseua_sysfs_entry *entry;
	struct ufseua_ctrl *eua_ctrl;
	ssize_t error;

	entry = container_of(attr, struct ufseua_sysfs_entry, attr);
	if (!entry->show)
		return -EIO;

	eua_ctrl = container_of(kobj, struct ufseua_ctrl, kobj);

	mutex_lock(&eua_ctrl->sysfs_lock);
	error = entry->show(eua_ctrl, page);
	mutex_unlock(&eua_ctrl->sysfs_lock);

	return error;
}

static ssize_t ufseua_attr_store(struct kobject *kobj, struct attribute *attr,
				 const char *page, size_t length)
{
	struct ufseua_sysfs_entry *entry;
	struct ufseua_ctrl *eua_ctrl;
	ssize_t error;

	entry = container_of(attr, struct ufseua_sysfs_entry, attr);
	if (!entry->store)
		return -EIO;

	eua_ctrl = container_of(kobj, struct ufseua_ctrl, kobj);

	mutex_lock(&eua_ctrl->sysfs_lock);
	error = entry->store(eua_ctrl, page, length);
	mutex_unlock(&eua_ctrl->sysfs_lock);

	return error;
}

static const struct sysfs_ops ufseua_sysfs_ops = {
	.show = ufseua_attr_show,
	.store = ufseua_attr_store,
};

static struct kobj_type ufseua_ktype = {
	.sysfs_ops = &ufseua_sysfs_ops,
	.release = NULL,
};

 int ufseua_create_sysfs(struct ufseua_ctrl *eua_ctrl)
{
	struct device *dev = eua_ctrl->hba->dev;
	struct ufseua_sysfs_entry *entry;
	int err;

	eua_ctrl->sysfs_entries = ufseua_sysfs_entries;

	kobject_init(&eua_ctrl->kobj, &ufseua_ktype);
	mutex_init(&eua_ctrl->sysfs_lock);

	pr_info("Creates sysfs %p dev->kobj %p",
		 &eua_ctrl->kobj, &dev->kobj);

	err = kobject_add(&eua_ctrl->kobj, kobject_get(&dev->kobj), "ufseua");
	if (!err) {
		for (entry = eua_ctrl->sysfs_entries; entry->attr.name != NULL;
		     entry++) {
			err = sysfs_create_file(&eua_ctrl->kobj, &entry->attr);
			if (err) {
				pr_err("Create entry(%s) failed",
					entry->attr.name);
				goto kobj_del;
			}
		}
		kobject_uevent(&eua_ctrl->kobj, KOBJ_ADD);
	} else {
		pr_err("Kobject_add failed");
	}

	return err;
kobj_del:
	err = kobject_uevent(&eua_ctrl->kobj, KOBJ_REMOVE);
	kobject_del(&eua_ctrl->kobj);
	return -EINVAL;
}

static inline void ufseua_remove_sysfs(struct ufseua_ctrl *eua_ctrl)
{
	int ret;

	ret = kobject_uevent(&eua_ctrl->kobj, KOBJ_REMOVE);
	pr_info("kobject removed (%d)", ret);
	kobject_del(&eua_ctrl->kobj);
}

int ufseua_probe(struct ufs_hba *hba)
{
	struct ufseua_ctrl *eua_ctrl;
	eua_ctrl = &hba->eua_ctrl;
	eua_ctrl->hba = hba;

	if (check_eua_policy(hba)){
		pr_info("[UFSEUA]Not Support EUA, Check Policy Fail");
		return -EOPNOTSUPP;
	}

	if (check_eua_total_raw_cap(hba)){
		pr_info("[UFSEUA]Not Support EUA, Check Raw Cap Fail");
		ufseua_check_fail();
		return -EOPNOTSUPP;
	}

	eua_ctrl->support = 1;
	ufseua_create_sysfs(eua_ctrl);

	pr_info("[UFSEUA]Support EUA Feture");

	return 0;
}

void ufseua_remove(struct ufs_hba *hba)
{
	mutex_lock(&hba->eua_ctrl.sysfs_lock);
	ufseua_remove_sysfs(&hba->eua_ctrl);
	mutex_unlock(&hba->eua_ctrl.sysfs_lock);
}
