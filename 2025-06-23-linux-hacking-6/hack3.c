/*
 * hack.c
 * kernel hacking: module params 2
 * author @cocomelonc
 * https://cocomelonc.github.io/linux/2025/06/23/kernel-hacking-6.html
 */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/moduleparam.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("cocomelonc");
MODULE_DESCRIPTION("kernel-test-03");
MODULE_VERSION("0.001");

static char *pet = "cat"; // default value is "cat"
static int count = 1; // default is 1
module_param(pet, charp, S_IRUSR | S_IWUSR);
module_param(count, int, S_IRUSR | S_IWUSR);
MODULE_PARM_DESC(pet, "Pet name: can be cat, mice, bird, dog, or sheep");
MODULE_PARM_DESC(count, "count");

static int __init hack_init(void) {
  int i;

  for (i = 0; i < count; i++) {
    // output the pet sound depending on the pet parameter
    if (strcmp(pet, "cat") == 0) {
        printk(KERN_INFO "Meow!\n");
    } else if (strcmp(pet, "mice") == 0) {
        printk(KERN_INFO "Squeak!\n");
    } else if (strcmp(pet, "bird") == 0) {
        printk(KERN_INFO "Twit-twit!\n");
    } else if (strcmp(pet, "dog") == 0) {
        printk(KERN_INFO "Woof!\n");
    } else if (strcmp(pet, "sheep") == 0) {
        printk(KERN_INFO "Baa baa!\n");
    } else {
        printk(KERN_INFO "unknown pet: %s\n", pet);
    }
  }

  return 0;
}

static void __exit hack_exit(void) {
  printk(KERN_INFO "meeeeeeeeeeeeeeeooooooow!\n");
}

module_init(hack_init);
module_exit(hack_exit);
