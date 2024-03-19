/*
 * mi_ufsswap.c
 *
 * Created on: 2023-06-01
 *
 * Authors:
 *	lijiaming <lijiaming3@xiaomi.com>
 */
#include <linux/pm_runtime.h>
#include "mi_ufsswap.h"
#include "../include/ufshcd.h"
#include "../include/ufs.h"
#include "../../ufs/host/ufs-qcom.h"
#include "../core/ufshcd-priv.h"

#define LBA_COUNT 5
#define WB_SS_LIMIT_BUF (1024/64*6/5)        //20% WB buf
#define WB_NONPINNED_LIMIT (2048*10/4)

inline int ufsswap_get_state(struct ufs_hba *hba)
{
	return atomic_read(&hba->swap_ctrl.swap_state);
}

inline void ufsswap_set_state(struct ufs_hba *hba, int state)
{
	atomic_set(&hba->swap_ctrl.swap_state, state);
}

static int ufsswap_is_not_present(struct ufsswap_ctrl *swap_ctrl)
{
	enum UFSSWAP_STATE cur_state = ufsswap_get_state(swap_ctrl->hba);

	if (cur_state != SWAP_PRESENT) {
		pr_info("[UFSSWAP]state != swap_PRESENT (%d)", cur_state);
		return -ENODEV;
	}
	return 0;
}

/* SS use attribute after fw 1801*/
struct ufsswap_dev_spec samsung_spec = {
	.idn_min_buf_size = QUERY_ATTR_IDN_SWAP_MIN_BUF_SIZE_SAMSUNG,
	.idn_max_buf_size = QUERY_ATTR_IDN_SWAP_MAX_BUF_SIZE_SAMSUNG,
	.idn_avail_buf_size = QUERY_ATTR_IDN_SWAP_AVAIL_BUF_SIZE_SAMSUNG,
	.idn_total_write_cnt = QUERY_ATTR_IDN_SWAP_TOTAL_WRITE_COUNT_SAMSUNG,
	.offset_max_buf_size = 0x0,
	.idn_need_enable_pin_buf = QUERY_ATTR_IDN_SWAP_NEED_ENABLE_PIN_BUF_SAMSUNG,
	.val_enable_pin_buf = 0x01,
	.gr_write = SWAP_WRITE_GROUP_NUM,
	.gr_read = 0x0
};

struct ufsswap_dev_spec hynix_spec = {
	.idn_min_buf_size = QUERY_ATTR_IDN_SWAP_MIN_BUF_SIZE_HYNIX,
	.idn_max_buf_size = QUERY_ATTR_IDN_SWAP_MAX_BUF_SIZE_HYNIX,
	.idn_avail_buf_size = QUERY_ATTR_IDN_SWAP_AVAIL_BUF_SIZE_HYNIX,
	.idn_total_write_cnt = QUERY_ATTR_IDN_SWAP_TOTAL_WRITE_COUNT_HYNIX,
	.offset_max_buf_size = 0x0,
	.idn_need_enable_pin_buf = 0x0,
	.val_enable_pin_buf = 0x0,
	.gr_write = SWAP_WRITE_GROUP_NUM,
	.gr_read = 0x0
};

struct ufsswap_dev_spec micron_spec = {
	.idn_min_buf_size = QUERY_ATTR_IDN_SWAP_MIN_BUF_SIZE_MICRON,
	.idn_max_buf_size = QUERY_ATTR_IDN_SWAP_MAX_BUF_SIZE_MICRON,
	.idn_avail_buf_size = QUERY_ATTR_IDN_SWAP_AVAIL_BUF_SIZE_MICRON,
	.idn_total_write_cnt = QUERY_ATTR_IDN_SWAP_TOTAL_WRITE_COUNT_MICRON,
	.offset_max_buf_size = 0x0,
	.idn_need_enable_pin_buf = 0x0,
	.val_enable_pin_buf = 0x0,
	.gr_write = SWAP_WRITE_GROUP_NUM,
	.gr_read = SWAP_READ_GROUP_NUM
};

struct ufsswap_dev_spec kioxia_spec = {
	.idn_min_buf_size = QUERY_ATTR_IDN_SWAP_MIN_BUF_SIZE_KIOXIA,
	.idn_max_buf_size = QUERY_ATTR_IDN_SWAP_MAX_BUF_SIZE_KIOXIA,
	.idn_avail_buf_size = QUERY_ATTR_IDN_SWAP_AVAIL_BUF_SIZE_KIOXIA,
	.idn_total_write_cnt = QUERY_ATTR_IDN_SWAP_TOTAL_WRITE_COUNT_KIOXIA,
	.offset_max_buf_size = 0x0,
	.idn_need_enable_pin_buf = QUERY_ATTR_IDN_SWAP_NEED_ENABLE_PIN_BUF_KIOXIA,
	.val_enable_pin_buf = 0x02,
	.gr_write = SWAP_WRITE_GROUP_NUM,
	.gr_read = 0x0
};

static int ufsswap_query_attr(struct ufs_hba *hba, enum query_opcode opcode, u8 idn,
			u8 idx, u8 selector, u32 *attr_val)
{
	int ret = 0;

	ufshcd_rpm_get_sync(hba);

	ret = ufshcd_query_attr_retry(hba, opcode, idn, idx,
				      selector, attr_val);
	if (ret)
		pr_err("[UFSSWAP]Query attr [0x%.2X] failed. opcode(%d) (%d)", idn, opcode, ret);

	pm_runtime_put_noidle(&hba->ufs_device_wlun->sdev_gendev);

	return ret;
}

static int ufsswap_read_desc(struct ufs_hba *hba, u8 desc_id, u8 desc_index,
			u8 selector, u8 *desc_buf, u32 size)
{
	int ret = 0;

	ufshcd_rpm_get_sync(hba);

	ret = mi_ufshcd_query_descriptor_retry(hba, UPIU_QUERY_OPCODE_READ_DESC,
					    desc_id, desc_index,
					    selector,
					    desc_buf, &size);

	if (ret)
		pr_err("[UFSSWAP]Read desc [0x%.2X] failed. (%d)", desc_id, ret);

	pm_runtime_put_noidle(&hba->ufs_device_wlun->sdev_gendev);

	return ret;
}

int ufsswap_flush_priority_control(struct ufsswap_ctrl *swap_ctrl)
{
	int ret = 0;
	int val = 0;
	u8 idn;
	struct ufs_hba *hba = swap_ctrl->hba;
	struct ufsswap_dev_info *swap_info = &swap_ctrl->swap_dev_info;

	idn = swap_info->swap_dev_spec->idn_need_enable_pin_buf;
	val = swap_info->swap_dev_spec->val_enable_pin_buf;

	ret = ufsswap_query_attr(hba, UPIU_QUERY_OPCODE_WRITE_ATTR,
			(enum attr_idn)idn, 0, 0, &val);
	if (ret)
		pr_err("[UFSSWAP]Query priority attr failed. ret(%d)", ret);

	return ret;
}

int ufsswap_get_swap_desc_info(struct ufsswap_ctrl *swap_ctrl)
{
	int ret;
	u8 *desc_buf;
	struct ufs_hba *hba = swap_ctrl->hba;
	struct ufsswap_dev_info *swap_info = &swap_ctrl->swap_dev_info;

	desc_buf = kmalloc(QUERY_DESC_MAX_SIZE, GFP_KERNEL);
	if (!desc_buf) {
		ret = -ENOMEM;
		return ret;
	}

	ret = ufsswap_read_desc(hba, QUERY_DESC_IDN_SWAP_MAX_BUF_SIZE_SAMSUNG, 0,
				0, desc_buf, QUERY_DESC_MAX_SIZE);
	if (ret) {
		pr_err("[UFSSWAP]Failed reading Desc. ret(%d)", ret);
		goto out;
	}

	swap_info->swap_max_buf_size = get_unaligned_be32(desc_buf +
		QUERY_DESC_OFFSET_SWAP_MAX_BUF_SIZE_SAMSUNG);

	ret = ufsswap_flush_priority_control(swap_ctrl);

out:
	kfree(desc_buf);
	return ret;
}

struct swap_policy_checklist {
	uint8_t vendor_id[9];
	uint8_t product_id[17];
	uint8_t product_rev[5];
	u32 density;
	struct ufsswap_dev_spec *dev_spec;
};

static struct swap_policy_checklist policy[] = {
	{"SKhynix", "HN8T174EJKX075",   "X202", 256,  &hynix_spec   },
	{"SKhynix", "HN8T274EJKX130",   "X202", 512,  &hynix_spec   },
	{"SKhynix", "HN8T374ZJKX141",   "X203", 1024, &hynix_spec   },
	{"SAMSUNG", "KLUGGARHHD-B0G1",  "1801", 1024, &samsung_spec },
	{"SAMSUNG", "KLUEG4RHHD-B0G1",  "1801", 256,  &samsung_spec },
	{"KIOXIA",  "THGJFLT2E46BATPB", "2100", 512,  &kioxia_spec  },
};

static int check_swap_policy(struct ufs_hba *hba)
{

	int i = 0;
	struct ufsswap_standard_inquiry stdinq = {};

	struct ufsswap_dev_info *swap_info = &hba->swap_ctrl.swap_dev_info;

	if(!hba->ufs_device_wlun){
		ERR_MSG("ufs_device_wlun init fail, maybe UFS had issues before this.");
		return -EOPNOTSUPP;
	}

	memcpy(&stdinq, hba->ufs_device_wlun->inquiry + 8, sizeof(stdinq));

	for (i = 0; i < sizeof(policy)/sizeof(policy[0]); i++) {
		if (!strncmp((char *)stdinq.vendor_id, (char *)policy[i].vendor_id, strlen((char *)policy[i].vendor_id))
			&& !strncmp((char *)stdinq.product_id, (char *)policy[i].product_id, strlen((char *)policy[i].product_id))
			&& !strncmp((char *)stdinq.product_rev, (char *)policy[i].product_rev, strlen((char *)policy[i].product_rev))) {
			swap_info->swap_dev_spec = policy[i].dev_spec;
			swap_info->density = policy[i].density;
			pr_info("[UFSSWAP]policy match[%d]", i + 1);
			if (!strncmp((char *)stdinq.product_rev, "X103", strlen("X103"))){
				pr_info("[UFSSWAP]sk X103 need change GR_num to 0x18");
				swap_info->swap_dev_spec->gr_read = 0x18;
			}
			return 0;
		}
	}

	return -EOPNOTSUPP;
}

static int ufsswap_get_dev_info(struct ufs_hba *hba, struct ufsswap_ctrl *swap_ctrl)
{
	int ret = -1;
	u32 val;
	u8 idn;

	struct ufsswap_dev_info *swap_info = &swap_ctrl->swap_dev_info;

	if(!hba->ufs_device_wlun){
		ERR_MSG("ufs_device_wlun init fail, maybe UFS had issues before this.");
		return ret;
	}

	if (swap_info->swap_dev_spec->idn_max_buf_size) {
		pr_info("[UFSSWAP] MAX BUF IDN: 0x%x\n", swap_info->swap_dev_spec->idn_max_buf_size);
		idn = swap_info->swap_dev_spec->idn_max_buf_size;
	} else {
		/*ss read desc before 1701,need read desc info*/
		pr_info("[UFSSWAP] IDN need get from desc configure\n");
		ret = ufsswap_get_swap_desc_info(swap_ctrl);
		return ret;
	}

	ret = ufsswap_query_attr(hba, UPIU_QUERY_OPCODE_READ_ATTR,
				idn, 0, 0, &val);
	if (ret) {
		pr_err("[UFSSWAP]Failed reading Attr. ret = %d\n", ret);
		return ret;
	}
	pr_info("[UFSSWAP] max buf size config size: 0x%x\n", val);
	swap_info->swap_max_buf_size = val;

	// get swap slc min_buf_size
	if (swap_info->swap_dev_spec->idn_min_buf_size) {
		idn = swap_info->swap_dev_spec->idn_min_buf_size;
		pr_info("[UFSSWAP] MIN BUF IDN: 0x%x\n", idn);
		ret = ufsswap_query_attr(hba, UPIU_QUERY_OPCODE_READ_ATTR,
					idn, 0, 0, &val);
		if (ret) {
			pr_err("[UFSSWAP]Failed reading Attr IDN MIN BUF. ret = %d\n", ret);
			return ret;
		}
	}
	pr_info("[UFSSWAP] min buf size config size: 0x%x\n", val);
	swap_info->swap_min_buf_size = val;

	if (swap_info->swap_max_buf_size && (swap_info->swap_dev_spec->idn_need_enable_pin_buf)) {
		ufsswap_flush_priority_control(swap_ctrl);
	}

	return ret;
}

unsigned int ufsswap_get_wb_buf(struct ufs_hba *hba, struct ufsswap_dev_info *swap_info)
{
	u32 wb_cur_buf = 0;
	int ret;

	// Get wb current buffer size
	ret = ufsswap_query_attr(hba, UPIU_QUERY_OPCODE_READ_ATTR,
				 QUERY_ATTR_IDN_CURR_WB_BUFF_SIZE, 0, 0, &wb_cur_buf);
	if (ret) {
		pr_info("[UFSSWAP] wb_cur_buf read failed %u\n", ret);
		return -EOPNOTSUPP;
	}
	if (!wb_cur_buf) {
		pr_info("[UFSSWAP] WB configuration exception! wb_cur_buf=%u\n", wb_cur_buf);
		return -EIO;
	}
	wb_cur_buf = wb_cur_buf*4;
	return wb_cur_buf;
}

int ufsswap_ss_config_wb_min_buf(struct ufs_hba *hba, struct ufsswap_ctrl *swap_dev)
{
	int ret = 0;
	int idn, attr;
	u32 wb_cur_buf = 0;
	struct ufsswap_dev_info *swap_info = &swap_dev->swap_dev_info;

	wb_cur_buf = ufsswap_get_wb_buf(hba, swap_info);
	if (swap_info->density == 256 &&
		swap_info->swap_dev_spec->idn_min_buf_size == QUERY_ATTR_IDN_SWAP_MIN_BUF_SIZE_SAMSUNG
		&& wb_cur_buf >= WB_NONPINNED_LIMIT) {
		attr = NON_PINNED_BUF_10GB;
		idn = QUERY_ATTR_IDN_SWAP_MIN_BUF_SIZE_SAMSUNG;
		ufsswap_query_attr(hba, UPIU_QUERY_OPCODE_WRITE_ATTR, idn, 0, 0, &attr);
		pr_info("[UFSSWAP] config non pinned buffer \n");
		if (ret) {
			pr_err("[UFSSWAP] Failed write SWAP Min Size. ret = %d\n", ret);
			return -EIO;
		}
	}
	return 0;
}

int ufsswap_config_swap_buf_size(struct ufs_hba *hba, struct ufsswap_ctrl *swap_dev)
{
	int ret = 0;
	int idn, attr;
	u32 wb_cur_buf = 0;
	u32 wb_limit_buf = 0;
	struct ufsswap_dev_info *swap_info = &swap_dev->swap_dev_info;

	wb_cur_buf = ufsswap_get_wb_buf(hba, swap_info);
	wb_limit_buf = swap_info->density*WB_SS_LIMIT_BUF;
	//If the WB lifespan expires and does not enter configuration
	if (wb_cur_buf <= wb_limit_buf) {
		pr_info("[UFSSWAP] SWAP SLC configure disable because WB not support.\n");
		return -EOPNOTSUPP;
	}
	attr = SWAP_SLC_10GB;
	pr_info("[UFSSWAP] SWAP SLC configure start\n");
	idn = swap_info->swap_dev_spec->idn_max_buf_size;
	ret = ufsswap_query_attr(hba, UPIU_QUERY_OPCODE_WRITE_ATTR, idn, 0,
				 0, &attr);
	if (ret) {
		pr_err("[UFSSWAP] Failed write SWAP Max Size. ret = %d\n", ret);
		return -EIO;
	}

	idn = swap_info->swap_dev_spec->idn_min_buf_size;
	if(idn == QUERY_ATTR_IDN_SWAP_MIN_BUF_SIZE_SAMSUNG)
	{
		attr = NON_PINNED_BUF_10GB;
	}else{
		attr = SWAP_WB_MIN_2GB;
	}
	ret = ufsswap_query_attr(hba, UPIU_QUERY_OPCODE_WRITE_ATTR, idn, 0,
				 0, &attr);
	if (ret) {
		pr_err("[UFSSWAP] Failed write SWAP Min Size. ret = %d\n", ret);
		return -EIO;
	}

	if (swap_info->swap_dev_spec->idn_need_enable_pin_buf) {
		ufsswap_flush_priority_control(swap_dev);
	}
	return 0;
}


static ssize_t ufsswap_sysfs_show_swap_support(struct ufsswap_ctrl *swap_ctrl, char *buf)
{
	u8 val = 0;

	if (swap_ctrl && swap_ctrl->swap_dev_info.swap_max_buf_size)
		val = 1;

	return sysfs_emit(buf, "%d\n", val);
}

static ssize_t ufsswap_sysfs_show_swap_file_lba_pre(struct ufsswap_ctrl *swap_ctrl, char *buf)
{
	struct ufsswap_lba_info *lba_info_tmp = NULL;
	struct list_head *head = &swap_ctrl->lba_list_head;
	int i = 0;
	int count = 0;
	u64 *lba_pre;
	u8 lba_judge_count = LBA_COUNT;

	if (list_empty(head))
		return count;

	lba_pre = kzalloc(swap_ctrl->swap_dev_info.swap_file_lba_count, GFP_KERNEL);
	if (!lba_pre)
		return -ENOMEM;

	list_for_each_entry(lba_info_tmp, head, list) {
		lba_pre[i] = lba_info_tmp->lba_pre;
		i++;
	}

	if (swap_ctrl->swap_dev_info.swap_file_lba_count <= LBA_COUNT)
		lba_judge_count = swap_ctrl->swap_dev_info.swap_file_lba_count;

	for(i = 0; i < lba_judge_count; i++) {
		count += snprintf(buf + count, PAGE_SIZE - count, "0x%x\n", lba_pre[i]);
	}

	kfree(lba_pre);
	return count;
}

static ssize_t ufsswap_sysfs_show_swap_file_lba_post(struct ufsswap_ctrl *swap_ctrl, char *buf)
{
	struct ufsswap_lba_info *lba_info_tmp = NULL;
	struct list_head *head = &swap_ctrl->lba_list_head;
	int i = 0;
	int count = 0;
	u64 *lba_post;
	u8 lba_judge_count = LBA_COUNT;

	if (list_empty(head))
		return count;

	lba_post = kzalloc(swap_ctrl->swap_dev_info.swap_file_lba_count, GFP_KERNEL);
	if (!lba_post)
		return -ENOMEM;

	list_for_each_entry(lba_info_tmp, head, list) {
		lba_post[i] = lba_info_tmp->lba_post;
		i++;
	}

	if (swap_ctrl->swap_dev_info.swap_file_lba_count <= LBA_COUNT)
		lba_judge_count = swap_ctrl->swap_dev_info.swap_file_lba_count;

	for(i = 0; i < lba_judge_count; i++) {
		count += snprintf(buf + count, PAGE_SIZE - count, "0x%x\n", lba_post[i]);
	}

	kfree(lba_post);
	return count;
}

static ssize_t ufsswap_sysfs_show_swap_max_buf_size(struct ufsswap_ctrl *swap_ctrl, char *buf)
{
	return sysfs_emit(buf, "%d\n", swap_ctrl->swap_dev_info.swap_max_buf_size);
}

static ssize_t ufsswap_sysfs_show_swap_avail_buf_size(struct ufsswap_ctrl *swap_ctrl, char *buf)
{
	u8 idn;
	int ret = 0, attr = -1;
	struct ufs_hba *hba = swap_ctrl->hba;
	struct ufsswap_dev_spec *swap_dev_spec = swap_ctrl->swap_dev_info.swap_dev_spec;

	idn = swap_dev_spec->idn_avail_buf_size;

	ret = ufsswap_query_attr(hba, UPIU_QUERY_OPCODE_READ_ATTR,
				idn, 0, 0, &attr);
	if (ret)
		pr_err("Failed reading SWAP Attr. ret = %d\n", ret);

	return sysfs_emit(buf, "%d\n", attr);
}

static ssize_t ufsswap_sysfs_show_swap_total_write_cnt(struct ufsswap_ctrl *swap_ctrl, char *buf)
{
	u8 idn;
	int ret = 0, attr = -1;
	struct ufs_hba *hba = swap_ctrl->hba;
	struct ufsswap_dev_spec *swap_dev_spec = swap_ctrl->swap_dev_info.swap_dev_spec;

	idn = swap_dev_spec->idn_total_write_cnt;

	ret = ufsswap_query_attr(hba, UPIU_QUERY_OPCODE_READ_ATTR,
				idn, 0, 0, &attr);
	if (ret)
		pr_err("Failed reading SWAP Attr. ret = %d\n", ret);

	return sysfs_emit(buf, "%d\n", attr);
}

static int ufsswap_check_lr_list_buf(struct ufsswap_ctrl *swap_ctrl, const char *buf)
{
	char *arg;
	int len = 0;

	if(!buf)
		return -EINVAL;

	arg = strstr(buf, ",");
	if(arg == NULL || buf[strlen(buf) - 1] == ',') {
		pr_err("[UFSSWAP]Invalid lba range, please input lba range separated by ','");
		return -EINVAL;
	}

	while (arg != NULL) {
		len++;
		arg +=1;
		arg = strstr(arg, ",");
	}
	if (len%2) {
		len++;
		pr_info("[UFSSWAP]Valid lba range count");
	} else {
		pr_err("[UFSSWAP]Invalid lba range count, please input again");
		return -EINVAL;
	}
	swap_ctrl->swap_dev_info.swap_file_lba_count = len/2;
	return 0;
}

static void ufsswap_sort(u64 *a, int length, int *b)
{
	int i,j;
	u64 tmp1;
	int tmp2;
	for(j = 0; j < length; j++)
		for(i = 0; i < length-1-j; i++)
			if(a[i] < a[i+1])
			{
				tmp1 = a[i];
				a[i] = a[i+1];
				a[i+1] = tmp1;

				tmp2 = b[i];
				b[i] = b[i+1];
				b[i+1] = tmp2;
			}
}

static int ufsswap_parser_buf(struct ufsswap_ctrl *swap_ctrl, const char *buf)
{
	int ret = 0;
	int i = 0, j = 0;
	char *buf_ptr; /* record raw lba info */
	char *lba_tmp; /* record lba after strsep */
	char *buf_ptr_org; /* record buf_ptr after kstrdup */
	u64 *lba_pre;
	u64 *lba_post;
	u64 *lba_length;
	int *lba_index;
	u64 lba_value_tmp;
	int len_index = 1;
	u8 lba_judge_count = LBA_COUNT;
	int lba_count = swap_ctrl->swap_dev_info.swap_file_lba_count;
	struct ufsswap_lba_info *lba_info;
#ifdef UFSSWAP_EBABLE
	struct list_head *head = &swap_ctrl->lba_list_head;
#endif
	struct device *dev = swap_ctrl->hba->dev;

	buf_ptr = kstrdup(buf, GFP_KERNEL);
	if (unlikely(!buf_ptr))
		return -ENOMEM;
	buf_ptr_org = buf_ptr;

	lba_pre = kzalloc(lba_count * sizeof(u64), GFP_KERNEL);
	if (!lba_pre) {
		ret = -ENOMEM;
		goto out_free_buf;
	}
	lba_post = kzalloc(lba_count * sizeof(u64), GFP_KERNEL);
	if (!lba_post) {
		ret = -ENOMEM;
		goto out_free_lba_pre;
	}

	lba_length = kzalloc(lba_count * sizeof(u64), GFP_KERNEL);
	if (!lba_length) {
		ret = -ENOMEM;
		goto out_free_lba_post;
	}

	lba_index = kzalloc(lba_count * sizeof(int), GFP_KERNEL);
	if (!lba_index) {
		ret = -ENOMEM;
		goto out_free_lba_length;
	}

	for (j = 0; j < lba_count; j++){
		lba_index[j] = j;
	}

	while((lba_tmp = strsep(&buf_ptr_org, ",")) != NULL) {
		ret = kstrtou64(lba_tmp, 16, &lba_value_tmp);
		if (ret) {
			ret = -ENODEV;
			goto out;
		}

		if (len_index % 2) {
			lba_pre[i] = lba_value_tmp;
		} else {
			if (lba_value_tmp < lba_pre[i]){
				ret = -EINVAL;
				goto out;
			}
			lba_post[i] = lba_value_tmp;
			lba_length[i] = lba_post[i] - lba_pre[i];
			i++;
		}
		len_index++;
	}
	ufsswap_sort(lba_length, lba_count, lba_index);

	if (swap_ctrl->swap_dev_info.swap_file_lba_count <= LBA_COUNT)
		lba_judge_count = swap_ctrl->swap_dev_info.swap_file_lba_count;

	for (i = 0; i < lba_judge_count; i++) {
		lba_info = devm_kzalloc(dev, sizeof(*lba_info), GFP_KERNEL);
		if (!lba_info) {
			ret = -ENOMEM;
			goto out;
		}
		lba_info->lba_pre = lba_pre[lba_index[i]];
		lba_info->lba_post = lba_post[lba_index[i]];
		pr_info("[UFSSWAP]lba pre[0x%x]post[0x%x]index[%d]\n",lba_info->lba_pre,lba_info->lba_post,lba_index[i]);
		list_add_tail(&lba_info->list, &swap_ctrl->lba_list_head);
	}
#ifdef UFSSWAP_EBABLE
	if (!list_empty(head))
		swap_ctrl->swap_enable = 1;
#endif

out:
	kfree(lba_index);
out_free_lba_length:
	kfree(lba_length);
out_free_lba_post:
	kfree(lba_post);
out_free_lba_pre:
	kfree(lba_pre);
out_free_buf:
	kfree(buf_ptr);

	return ret;
}

static ssize_t ufsswap_sysfs_store_swap_file_lba_info(struct ufsswap_ctrl *swap_ctrl,
						      const char *buf,
						      size_t count)
{
	int ret = 0;

	list_del_init(&swap_ctrl->lba_list_head);

	ret = ufsswap_check_lr_list_buf(swap_ctrl, buf);
	if (ret)
		return -EINVAL;

	ret = ufsswap_parser_buf(swap_ctrl, buf);
	if (ret) {
		pr_err("parser lba range failed");
		return -EINVAL;
	}

	return count;
}

static ssize_t ufsswap_sysfs_show_swap_enable(struct ufsswap_ctrl *swap_ctrl, char *buf)
{
	return sysfs_emit(buf, "%d\n", swap_ctrl->swap_enable);
}

static ssize_t ufsswap_sysfs_store_swap_enable(struct ufsswap_ctrl *swap_ctrl,
						      const char *buf,
						      size_t count)
{
	unsigned long val;

	if (kstrtoul(buf, 0, &val))
		return -EINVAL;

	if (val != 0 && val != 1)
		return -EINVAL;

	swap_ctrl->swap_enable = val;

	return count;
}

#define define_sysfs_ro(_name) __ATTR(_name, 0444,			\
				      ufsswap_sysfs_show_##_name, NULL)
#define define_sysfs_wo(_name) __ATTR(_name, 0200,			\
				       NULL, ufsswap_sysfs_store_##_name)
#define define_sysfs_rw(_name) __ATTR(_name, 0644,			\
				      ufsswap_sysfs_show_##_name,	\
				      ufsswap_sysfs_store_##_name)

static struct ufsswap_sysfs_entry ufsswap_sysfs_entries[] = {
	define_sysfs_ro(swap_support),
	define_sysfs_ro(swap_max_buf_size),
	define_sysfs_ro(swap_avail_buf_size),
	define_sysfs_ro(swap_total_write_cnt),
	define_sysfs_ro(swap_file_lba_pre),
	define_sysfs_ro(swap_file_lba_post),
	define_sysfs_wo(swap_file_lba_info),
	define_sysfs_rw(swap_enable),
	__ATTR_NULL
};

static ssize_t ufsswap_attr_show(struct kobject *kobj, struct attribute *attr,
				char *page)
{
	struct ufsswap_sysfs_entry *entry;
	struct ufsswap_ctrl *swap_ctrl;
	ssize_t error;

	entry = container_of(attr, struct ufsswap_sysfs_entry, attr);
	if (!entry->show)
		return -EIO;

	swap_ctrl = container_of(kobj, struct ufsswap_ctrl, kobj);
	if (ufsswap_is_not_present(swap_ctrl))
		return -ENODEV;

	mutex_lock(&swap_ctrl->sysfs_lock);
	error = entry->show(swap_ctrl, page);
	mutex_unlock(&swap_ctrl->sysfs_lock);

	return error;
}

static ssize_t ufsswap_attr_store(struct kobject *kobj, struct attribute *attr,
				 const char *page, size_t length)
{
	struct ufsswap_sysfs_entry *entry;
	struct ufsswap_ctrl *swap_ctrl;
	ssize_t error;

	entry = container_of(attr, struct ufsswap_sysfs_entry, attr);
	if (!entry->store)
		return -EIO;

	swap_ctrl = container_of(kobj, struct ufsswap_ctrl, kobj);
	if (ufsswap_is_not_present(swap_ctrl))
		return -ENODEV;

	mutex_lock(&swap_ctrl->sysfs_lock);
	error = entry->store(swap_ctrl, page, length);
	mutex_unlock(&swap_ctrl->sysfs_lock);

	return error;
}

static const struct sysfs_ops ufsswap_sysfs_ops = {
	.show = ufsswap_attr_show,
	.store = ufsswap_attr_store,
};

static struct kobj_type ufsswap_ktype = {
	.sysfs_ops = &ufsswap_sysfs_ops,
	.release = NULL,
};

 int ufsswap_create_sysfs(struct ufsswap_ctrl *swap_ctrl)
{
	struct device *dev = swap_ctrl->hba->dev;
	struct ufsswap_sysfs_entry *entry;
	int err;

	swap_ctrl->sysfs_entries = ufsswap_sysfs_entries;

	kobject_init(&swap_ctrl->kobj, &ufsswap_ktype);
	mutex_init(&swap_ctrl->sysfs_lock);

	pr_info("Creates sysfs %p dev->kobj %p",
		 &swap_ctrl->kobj, &dev->kobj);

	err = kobject_add(&swap_ctrl->kobj, kobject_get(&dev->kobj), "ufsswap");
	if (!err) {
		for (entry = swap_ctrl->sysfs_entries; entry->attr.name != NULL;
		     entry++) {
			err = sysfs_create_file(&swap_ctrl->kobj, &entry->attr);
			if (err) {
				pr_err("Create entry(%s) failed",
					entry->attr.name);
				goto kobj_del;
			}
		}
		kobject_uevent(&swap_ctrl->kobj, KOBJ_ADD);
	} else {
		pr_err("Kobject_add failed");
	}

	return err;
kobj_del:
	err = kobject_uevent(&swap_ctrl->kobj, KOBJ_REMOVE);
	kobject_del(&swap_ctrl->kobj);
	return -EINVAL;
}

static inline void ufsswap_remove_sysfs(struct ufsswap_ctrl *swap_ctrl)
{
	int ret;

	ret = kobject_uevent(&swap_ctrl->kobj, KOBJ_REMOVE);
	pr_info("kobject removed (%d)", ret);
	kobject_del(&swap_ctrl->kobj);
}

int ufsswap_probe(struct ufs_hba *hba)
{
	struct ufsswap_ctrl *swap_ctrl;
	swap_ctrl = &hba->swap_ctrl;
	swap_ctrl->hba = hba;

	pr_info("[UFSSWAP] %s Enter", __func__);
	if (check_swap_policy(hba))
		return -EOPNOTSUPP;

	if (ufsswap_get_dev_info(hba, swap_ctrl)) {
		pr_err("[UFSSWAP] Get SWAP SLC configure parameter failed\n");
		return -EOPNOTSUPP;

	}

	if (!swap_ctrl->swap_dev_info.swap_max_buf_size) { //no configure swap slc, try config again
		if (ufsswap_config_swap_buf_size(hba, swap_ctrl)) {
			pr_err("[UFSSWAP] SWAP SLC configure failed\n");
			return -EOPNOTSUPP;
		}

		if (ufsswap_get_dev_info(hba, swap_ctrl) || (!swap_ctrl->swap_dev_info.swap_max_buf_size)) {
			pr_err("[UFSSWAP] Retry Get the SWAP SLC parameters is no match,NEED check!!!\n");
			return -EOPNOTSUPP;
		}
	}
	if (swap_ctrl->swap_dev_info.swap_min_buf_size == 0x200) {
		if (ufsswap_ss_config_wb_min_buf(hba, swap_ctrl)) {
			pr_err("[UFSSWAP] samsung min wb buf configure failed\n");
			return -EOPNOTSUPP;
		}
	}
	INIT_LIST_HEAD(&swap_ctrl->lba_list_head);
	ufsswap_create_sysfs(swap_ctrl);
	ufsswap_set_state(hba, SWAP_PRESENT);

	return 0;
}

void ufsswap_remove(struct ufs_hba *hba)
{
	mutex_lock(&hba->swap_ctrl.sysfs_lock);
	ufsswap_remove_sysfs(&hba->swap_ctrl);
	mutex_unlock(&hba->swap_ctrl.sysfs_lock);
}
