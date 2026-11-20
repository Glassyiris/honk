APP_OPTIM := release
APP_PLATFORM := android-29
APP_ABI := arm64-v8a
# Register hev's natives on dev.tunbench.TProxyService instead of hev.htproxy.TProxyService.
APP_CFLAGS := -O3 -DPKGNAME=dev/tunbench -DCLSNAME=TProxyService
APP_SUPPORT_FLEXIBLE_PAGE_SIZES := true
