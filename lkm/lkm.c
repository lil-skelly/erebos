/* Bare-bones LKM (Loaded Kernel Module) to use with the loader */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>

MODULE_LICENSE("AGPL");
MODULE_AUTHOR("lil-skelly");
MODULE_DESCRIPTION("Basic LKM for the Erebos loader");
MODULE_VERSION("1.0");

static int __init lkm_init(void) {
  pr_info("lkm: Loaded sample LKM.\n");
  return 0;
}

static void __exit lkm_exit(void) {
    pr_info("lkm: Unloaded sample LKM.\n");
}

module_init(lkm_init);
module_exit(lkm_exit);
