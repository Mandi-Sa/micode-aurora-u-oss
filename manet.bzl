load(":target_variants.bzl", "la_variants")
load(":msm_kernel_la.bzl", "define_msm_la")
load(":image_opts.bzl", "boot_image_opts")
load(":pineapple.bzl", "target_arch", "target_arch_in_tree_modules", "target_arch_consolidate_in_tree_modules", "target_arch_kernel_vendor_cmdline_extras", "target_arch_board_kernel_cmdline_extras", "target_arch_board_bootconfig_extras")
load(":xiaomi_sm8650_common.bzl", "xiaomi_common_in_tree_modules", "xiaomi_common_consolidate_in_tree_modules")
target_name = "manet"

def define_manet():
    _target_in_tree_modules = target_arch_in_tree_modules + \
        xiaomi_common_in_tree_modules + [
        # keep sorted
        "drivers/staging/binder_prio/binder_prio.ko",
        "drivers/input/fingerprint/goodix_fod/goodix_fod.ko",
        "drivers/regulator/wl2868c.ko",
        "drivers/power/xm_power/xm_power.ko",
        "drivers/mihw/mi_sched/mi_schedule.ko",
        "drivers/mihw/metis/metis.ko",
        "drivers/mihw/game/migt.ko",
	"drivers/staging/miev/miev.ko",
        "drivers/staging/mi-log/mi_log.ko",
        "drivers/staging/mi-log/mi_exception_log.ko",
        "drivers/staging/mi-perf/mi_mempool/mi_mempool.ko",
        ]

    _target_consolidate_in_tree_modules = _target_in_tree_modules + \
            target_arch_consolidate_in_tree_modules + \
            xiaomi_common_consolidate_in_tree_modules + [
        # keep sorted
        ]
    kernel_vendor_cmdline_extras = list(target_arch_kernel_vendor_cmdline_extras)
    board_kernel_cmdline_extras = list(target_arch_board_kernel_cmdline_extras)
    board_bootconfig_extras = list(target_arch_board_bootconfig_extras)

    for variant in la_variants:
        if variant == "consolidate":
            mod_list = _target_consolidate_in_tree_modules
        else:
            mod_list = _target_in_tree_modules
            board_kernel_cmdline_extras += ["nosoftlockup"]
            kernel_vendor_cmdline_extras += ["nosoftlockup"]
            board_bootconfig_extras += ["androidboot.console=0"]
        define_msm_la(
            msm_target = target_name,
            msm_arch = target_arch,
            variant = variant,
            in_tree_module_list = mod_list,
            boot_image_opts = boot_image_opts(
                earlycon_addr = "qcom_geni,0x00a9C000",
                kernel_vendor_cmdline_extras = kernel_vendor_cmdline_extras,
                board_kernel_cmdline_extras = board_kernel_cmdline_extras,
                board_bootconfig_extras = board_bootconfig_extras,
            )
        )
