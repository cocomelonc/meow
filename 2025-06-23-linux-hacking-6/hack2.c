/*
 * hack.c
 * kernel hacking: module params
 * author @cocomelonc
 * https://cocomelonc.github.io/linux/2025/06/23/kernel-hacking-6.html
 */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/moduleparam.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("cocomelonc");
MODULE_DESCRIPTION("kernel-test-02");
MODULE_VERSION("0.001");

static char *pet = "cat"; // default value is "cat"
module_param(pet, charp, S_IRUSR | S_IWUSR);
MODULE_PARM_DESC(pet, "Pet name: can be cat, mice, bird, dog, or sheep");

static int __init hack_init(void) {
  if (strcmp(pet, "cat") == 0) {
    printk(KERN_INFO "Meow-meow!\n");
  } else if (strcmp(pet, "mice") == 0) {
    printk(KERN_INFO "Squeak-squeak!\n");
  } else if (strcmp(pet, "bird") == 0) {
    printk(KERN_INFO "Twit-twit!\n");
  } else if (strcmp(pet, "dog") == 0) {
    printk(KERN_INFO "Woof-woof!\n");
  } else if (strcmp(pet, "sheep") == 0) {
    printk(KERN_INFO "Baa-baa!\n");
  } else {
    printk(KERN_INFO "unknown pet: %s\n", pet);
  }
  return 0;
}

static void __exit hack_exit(void) {
  printk(KERN_INFO "meeeeeeeeeeeeeeeooooooow!\n");
}

module_init(hack_init);
module_exit(hack_exit);
