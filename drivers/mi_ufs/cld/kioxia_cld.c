/*
 * mi_cld1.c
 *
 *  Created on: 2020-10-20
 *      Author: shane
 */

#include "mi_cld.h"
#include "../include/ufshcd.h"

#define GEN11_QUERY_FLAG_IDN_CLD_ENABLE 0x13
#define GEN11_QUERY_ATTR_IDN_CLD_LEVEL 0x34
#define GEN11_QUERY_ATTR_IDN_DEFRAG 0x35

#define GEN12_QUERY_FLAG_IDN_CLD_ENABLE 0xA0
#define GEN12_QUERY_ATTR_IDN_CLD_LEVEL 0xA0
#define GEN12_QUERY_ATTR_IDN_DEFRAG 0xA1

static int query_attr_flag_cld_enable;
static int query_attr_idn_cld_level;
static int query_attr_idn_defrag;

enum KIOXIA_DEFRAG {
	DEFRAG_IDEL = 0x0,
	DEFRAG_OPERATING = 0x01,
	DEFRAG_OPERATION_STOPPED = 0x02,
	DEFRAG_OPERATION_COMPLETED = 0x03,
	DEFRAG_OPERATION_FAILURE = 0x04,
};

int kioxia_init_idn(struct standard_inquiry stdinq)
{
	int ret = 0;
	// "FL" is Gen12, "FJ" is Gen11
	if (strncmp((char *)stdinq.vendor_id, "KIOXIA", 6) == 0) {
		if (strncmp((char *)stdinq.product_id, "THGJFL", 6) == 0) {
			INFO_MSG("KIOXIA UFS is Gen12");
			query_attr_flag_cld_enable = GEN12_QUERY_FLAG_IDN_CLD_ENABLE;
			query_attr_idn_cld_level = GEN12_QUERY_ATTR_IDN_CLD_LEVEL;
			query_attr_idn_defrag = GEN12_QUERY_ATTR_IDN_DEFRAG;
		} else if(strncmp((char *)stdinq.product_id, "THGJFJ", 6) == 0){
			INFO_MSG("KIOXIA UFS is Gen11");
			query_attr_flag_cld_enable = GEN11_QUERY_FLAG_IDN_CLD_ENABLE;
			query_attr_idn_cld_level = GEN11_QUERY_ATTR_IDN_CLD_LEVEL;
			query_attr_idn_defrag = GEN11_QUERY_ATTR_IDN_DEFRAG;
		} else{
			ERR_MSG("Please check KIOXIA datasheet.");
			ret = -1;
		}
	}
	return ret;
}

int kioxia_get_frag_level(struct ufscld_dev *cld, int *frag_level)
{
	struct ufs_hba *hba = cld->hba;
	int ret = 0, attr = -1;
	ret = ufshcd_query_attr_retry(hba, UPIU_QUERY_OPCODE_READ_ATTR, (enum attr_idn)query_attr_idn_cld_level, 0, 0, &attr);
	if (ret)
		return ret;
	if (attr == 0) {
		*frag_level = CLD_LEV_CLEAN;
	} else if (attr == 1) {
		*frag_level = CLD_LEV_WARN;
	} else if (attr == 2 || attr == 3) {
		*frag_level= CLD_LEV_CRITICAL;
	}else {
		pr_info("kioxia cld unknown level %d\n", attr);
		ret = -1;
		return ret;
	}
	return 0;
}

int kioxia_cld_set_trigger(struct ufscld_dev *cld, u32 trigger)
{
	struct ufs_hba *hba = cld->hba;
	if (trigger)
		return ufshcd_query_flag_retry(hba, UPIU_QUERY_OPCODE_SET_FLAG, (enum flag_idn)query_attr_flag_cld_enable, 0, NULL);
	else
		return ufshcd_query_flag_retry(hba, UPIU_QUERY_OPCODE_CLEAR_FLAG, (enum flag_idn)query_attr_flag_cld_enable, 0, NULL);
}

int kioxia_cld_get_trigger(struct ufscld_dev *cld, u32 *trigger)
{
	struct ufs_hba *hba = cld->hba;

	return ufshcd_query_flag_retry(hba, UPIU_QUERY_OPCODE_READ_FLAG, (enum flag_idn)query_attr_flag_cld_enable, 0,(bool *)trigger);
}

static int kioxia_cld_get_defragprogress(struct ufscld_dev *cld, int *defragprogress)
{
	struct ufs_hba *hba = cld->hba;
	int ret = 0;

	*defragprogress = 0;

	ret = ufshcd_query_attr_retry(hba, UPIU_QUERY_OPCODE_READ_ATTR, (enum attr_idn)query_attr_idn_defrag, 0, 0, defragprogress);

	return 0;
}

int kioxia_cld_operation_status(struct ufscld_dev *cld, int *op_status)
{
	int ret = 0;
	int defragprogress = 0;

	ret = kioxia_cld_get_defragprogress(cld, &defragprogress);
	if (ret)
		ERR_MSG("get defragprogress failed ret=%d\n", ret);

	if (defragprogress == DEFRAG_IDEL || defragprogress == DEFRAG_OPERATION_COMPLETED || \
		 defragprogress == DEFRAG_OPERATION_FAILURE) {// if cld was done
		*op_status = CLD_STATUS_IDLE;
	} else if (defragprogress == DEFRAG_OPERATING || defragprogress == DEFRAG_OPERATION_STOPPED){
		*op_status = CLD_STATUS_PROGRESSING;
	} else {
		*op_status = CLD_STATUS_NA;
	}

	return 0;
}

struct ufscld_ops kioxia_cld_ops = {
		.cld_get_frag_level = kioxia_get_frag_level,
		.cld_set_trigger = kioxia_cld_set_trigger,
		.cld_get_trigger = kioxia_cld_get_trigger,
		.cld_operation_status = kioxia_cld_operation_status
};
