/*
 * hack.c
 * introduction to linux kernel hacking
 * author @cocomelonc
 * https://cocomelonc.github.io/linux/2025/06/23/kernel-hacking-6.html
*/
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("cocomelonc");
MODULE_DESCRIPTION("kernel-test-01");
MODULE_VERSION("0.001");

static int __init hack_init(void) {
  printk(KERN_INFO "Meow-meow!\n");
  return 0;
}

static void __exit hack_exit(void) {
  printk(KERN_INFO "Meow-bow!\n");
}

module_init(hack_init);
module_exit(hack_exit);
