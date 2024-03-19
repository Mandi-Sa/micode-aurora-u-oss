/*
 * mi_cld1.c
 *
 *  Created on: 2020-10-20
 *      Author: shane
 */

#include <linux/delay.h>

#include "mi_cld.h"
#include "../include/ufshcd.h"

#define QUERY_ATTR_IDN_CLD_ENABLE 0x80
#define QUERY_ATTR_IDN_CLD_LEVEL 0x81
#define HID_SELECTOR 0
#define CLD_WAIT_CLEAN_TIMES 20000

#define CLD_FRAG_LEVEL_MASK		0xF
#define CLD_GET_FRAG_LEVEL(val)		(val & CLD_FRAG_LEVEL_MASK)
#define CLD_EXECUTE_REQ_STAT_SHIFT	31
#define CLD_EXECUTE_REQ_STAT(val)	((val >> CLD_EXECUTE_REQ_STAT_SHIFT) & 0x1)
static int cld_req_stat; // 1 CLD_REQUIRED, 0 CLD_NOT_REQUIRED

int samsung_get_frag_level(struct ufscld_dev *cld, int *frag_level)
{
	struct ufs_hba *hba = cld->hba;
	int ret = 0, attr = -1, level;
	attr = 1; // do analyze
	ret =  ufshcd_query_attr_retry(hba, UPIU_QUERY_OPCODE_WRITE_ATTR, (enum attr_idn)QUERY_ATTR_IDN_CLD_ENABLE, 0, HID_SELECTOR, &attr);
	if (ret) {
		ERR_MSG("do analysis fail. op code=UPIU_QUERY_OPCODE_WRITE_ATTR, attr_id=%d\n", (int)QUERY_ATTR_IDN_CLD_ENABLE);
		return ret;
	}

	msleep(200);

	ret = ufshcd_query_attr_retry(hba, UPIU_QUERY_OPCODE_READ_ATTR, (enum attr_idn)QUERY_ATTR_IDN_CLD_LEVEL, 0, HID_SELECTOR, &attr);
	if (ret) {
		ERR_MSG("read frag level  fail,op code=UPIU_QUERY_OPCODE_READ_ATTR, attr_id=%d\n", (int)QUERY_ATTR_IDN_CLD_LEVEL);
		return ret;
	}

	level = CLD_GET_FRAG_LEVEL(attr);
	cld_req_stat = CLD_EXECUTE_REQ_STAT(attr);

	INFO_MSG("get_level pass, attr=0x%x, cld_req_stat=%d.\n", attr, cld_req_stat);

	if (level == 0) {
		*frag_level = CLD_LEV_NA;
	} else if (level == 1) {
		*frag_level = CLD_LEV_CLEAN;
	} else if (level == 2) {
		*frag_level = CLD_LEV_WARN;
	} else if (level == 3) {
		*frag_level = CLD_LEV_CRITICAL;
	} else {
		pr_info("samsung cld unknown level %d\n", *frag_level);
		ret = -1;
		return ret;
	}
	return 0;
}

int samsung_cld_set_trigger(struct ufscld_dev *cld, u32 trigger)
{
	struct ufs_hba *hba = cld->hba;
	int ret = 0;

	if (trigger)
		trigger  = 2;// execute after analyze.

	ret =  ufshcd_query_attr_retry(hba, UPIU_QUERY_OPCODE_WRITE_ATTR, (enum attr_idn)QUERY_ATTR_IDN_CLD_ENABLE, 0, HID_SELECTOR, &trigger);

	if (ret) {
		ERR_MSG("send execute afger analysis  failed. attr_idn=%d, opcode=UPIU_QUERY_OPCODE_WRITE_ATTR, trigger=%d", QUERY_ATTR_IDN_CLD_ENABLE, trigger);
	}

	return ret;
}

int samsung_cld_get_trigger(struct ufscld_dev *cld, u32 *trigger)
{
	struct ufs_hba *hba = cld->hba;
	int ret = 0;

	ret =  ufshcd_query_attr_retry(hba, UPIU_QUERY_OPCODE_READ_ATTR, (enum attr_idn)QUERY_ATTR_IDN_CLD_ENABLE, 0, HID_SELECTOR, trigger);

	if (ret) {
		ERR_MSG("read cld trigger  failed. attr_idn=%d, opcode=UPIU_QUERY_OPCODE_WRITE_ATTR, trigger=%d", QUERY_ATTR_IDN_CLD_ENABLE, trigger);
	}

	return ret;
}

int samsung_cld_operation_status(struct ufscld_dev *cld, int *op_status)
{
	enum CLD_LEVEL frag_level;
	enum CLD_STATUS op_status_tmp;
	int ret = 0;
	ktime_t delta_time_stamp = 0;

	ret = samsung_get_frag_level(cld, (int*) &frag_level);
	if (ret)
		ERR_MSG("get frag level failed ret=%d\n", ret);

	if ( (frag_level == CLD_LEV_CLEAN || frag_level == CLD_LEV_NA) || cld_req_stat == 0) {// if cld was done or cld is not required
		op_status_tmp = CLD_STATUS_IDLE;
	} else if (frag_level == CLD_LEV_WARN || frag_level == CLD_LEV_CRITICAL){
		op_status_tmp = CLD_STATUS_PROGRESSING;
	} else {
		op_status_tmp = CLD_STATUS_NA;
	}

	delta_time_stamp = ktime_to_ms(ktime_get()) - cld->start_time_stamp;

	if (op_status_tmp == CLD_STATUS_IDLE) {
		if (delta_time_stamp >= CLD_WAIT_CLEAN_TIMES) {
			cld->start_time_stamp = ktime_to_ms(ktime_get());
			*op_status = CLD_STATUS_IDLE;
		} else {
			*op_status = CLD_STATUS_PROGRESSING;
		}
	} else {
		cld->start_time_stamp = ktime_to_ms(ktime_get());
		*op_status = op_status_tmp;
	}

	return 0;
}

struct ufscld_ops samsung_cld_ops = {
		.cld_get_frag_level = samsung_get_frag_level,
		.cld_set_trigger = samsung_cld_set_trigger,
		.cld_get_trigger = samsung_cld_get_trigger,
		.cld_operation_status = samsung_cld_operation_status
};
