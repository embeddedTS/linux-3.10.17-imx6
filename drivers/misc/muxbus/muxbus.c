/*
 * Copyright (C) 2014, Technologic Systems, Inc
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
 
 
/* 
   A somewhat brute-force approach to muxbus.  All the muxbus lines are 
   GPIO, wiggled as needed.
*/

#include <linux/err.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/major.h>
#include <linux/cdev.h>
#include <linux/delay.h>
#include <linux/gpio.h>
#include <asm/io.h>
#include <asm/uaccess.h>
#include <linux/platform_device.h>

#include <../arch/arm/mach-imx/hardware.h>
#include <../arch/arm/mach-imx/mx6.h>

#define MIN(x,y)  (((x)<(y))?(x):(y))

static struct muxbus_dev {
   struct cdev cdev;
   dev_t dev;      
} muxbus_dev ;


#define MUXBUS_CSN_GPIO   IMX_GPIO_NR(2, 23)
#define MUXBUS_DIR_GPIO   IMX_GPIO_NR(2, 26)
#define MUXBUS_ALEN_GPIO  IMX_GPIO_NR(2, 27)
#define MUXBUS_BHEN_GPIO  IMX_GPIO_NR(3, 31)
#define MUXBUS_AD00_GPIO  IMX_GPIO_NR(3, 0)
#define MUXBUS_AD01_GPIO  IMX_GPIO_NR(3, 1)
#define MUXBUS_AD02_GPIO  IMX_GPIO_NR(3, 2)
#define MUXBUS_AD03_GPIO  IMX_GPIO_NR(3, 3)
#define MUXBUS_AD04_GPIO  IMX_GPIO_NR(3, 4)
#define MUXBUS_AD05_GPIO  IMX_GPIO_NR(3, 5)
#define MUXBUS_AD06_GPIO  IMX_GPIO_NR(3, 6)
#define MUXBUS_AD07_GPIO  IMX_GPIO_NR(3, 7)
#define MUXBUS_AD08_GPIO  IMX_GPIO_NR(3, 8)
#define MUXBUS_AD09_GPIO  IMX_GPIO_NR(3, 9)
#define MUXBUS_AD10_GPIO  IMX_GPIO_NR(3, 10)
#define MUXBUS_AD11_GPIO  IMX_GPIO_NR(3, 11)
#define MUXBUS_AD12_GPIO  IMX_GPIO_NR(3, 12)
#define MUXBUS_AD13_GPIO  IMX_GPIO_NR(3, 13)
#define MUXBUS_AD14_GPIO  IMX_GPIO_NR(3, 14)
#define MUXBUS_AD15_GPIO  IMX_GPIO_NR(3, 15)
#define MUXBUS_WAITN_GPIO IMX_GPIO_NR(5, 0)

static struct gpio  muxbus_gpio_pins[] = {
      
   { MUXBUS_AD00_GPIO, GPIOF_DIR_IN | GPIOF_EXPORT_DIR_CHANGEABLE, "muxbus AD0" },   
   { MUXBUS_AD01_GPIO, GPIOF_DIR_IN | GPIOF_EXPORT_DIR_CHANGEABLE, "muxbus AD1" },
   { MUXBUS_AD02_GPIO, GPIOF_DIR_IN | GPIOF_EXPORT_DIR_CHANGEABLE, "muxbus AD2" },
   { MUXBUS_AD03_GPIO, GPIOF_DIR_IN | GPIOF_EXPORT_DIR_CHANGEABLE, "muxbus AD3" },
   { MUXBUS_AD04_GPIO, GPIOF_DIR_IN | GPIOF_EXPORT_DIR_CHANGEABLE, "muxbus AD4" },
   { MUXBUS_AD05_GPIO, GPIOF_DIR_IN | GPIOF_EXPORT_DIR_CHANGEABLE, "muxbus AD5" },
   { MUXBUS_AD06_GPIO, GPIOF_DIR_IN | GPIOF_EXPORT_DIR_CHANGEABLE, "muxbus AD6" },
   { MUXBUS_AD07_GPIO, GPIOF_DIR_IN | GPIOF_EXPORT_DIR_CHANGEABLE, "muxbus AD7" },
   { MUXBUS_AD08_GPIO, GPIOF_DIR_IN | GPIOF_EXPORT_DIR_CHANGEABLE, "muxbus AD8" },
   { MUXBUS_AD09_GPIO, GPIOF_DIR_IN | GPIOF_EXPORT_DIR_CHANGEABLE, "muxbus AD9" },
   { MUXBUS_AD10_GPIO, GPIOF_DIR_IN | GPIOF_EXPORT_DIR_CHANGEABLE, "muxbus AD10" },
   { MUXBUS_AD11_GPIO, GPIOF_DIR_IN | GPIOF_EXPORT_DIR_CHANGEABLE, "muxbus AD11" },
   { MUXBUS_AD12_GPIO, GPIOF_DIR_IN | GPIOF_EXPORT_DIR_CHANGEABLE, "muxbus AD12" },
   { MUXBUS_AD13_GPIO, GPIOF_DIR_IN | GPIOF_EXPORT_DIR_CHANGEABLE, "muxbus AD13" },
   { MUXBUS_AD14_GPIO, GPIOF_DIR_IN | GPIOF_EXPORT_DIR_CHANGEABLE, "muxbus AD14" },
   { MUXBUS_AD15_GPIO, GPIOF_DIR_IN | GPIOF_EXPORT_DIR_CHANGEABLE, "muxbus AD15" },
   
   { MUXBUS_CSN_GPIO, GPIOF_OUT_INIT_HIGH | GPIOF_EXPORT,   "muxbus CS#" },
   { MUXBUS_DIR_GPIO, GPIOF_OUT_INIT_HIGH | GPIOF_EXPORT,   "muxbus DIR" },
   { MUXBUS_ALEN_GPIO, GPIOF_OUT_INIT_HIGH | GPIOF_EXPORT,  "muxbus ALE#" },
   { MUXBUS_BHEN_GPIO, GPIOF_OUT_INIT_HIGH | GPIOF_EXPORT,  "muxbus BHE#" },
   
   { MUXBUS_WAITN_GPIO, GPIOF_DIR_IN,        "muxbus WAIT#" },

};   
   


static inline void muxbus_bhe(int level)
{
   gpio_set_value(MUXBUS_BHEN_GPIO, level);
}


static inline void muxbus_ale(int level)
{   
   gpio_set_value(MUXBUS_ALEN_GPIO, level);
}

static inline void muxbus_dir(int level)
{
   gpio_set_value(MUXBUS_DIR_GPIO, level);
}


static inline void muxbus_cs0(int level)
{  
   gpio_set_value(MUXBUS_CSN_GPIO, level);
}

static inline void muxbus_data(void)
{   
   /* make address lines [15:0] inputs (for data) */
   int n;
       
   for(n=0; n < 16; n++) {
      gpio_direction_input(muxbus_gpio_pins[n].gpio);            
   }
}

static inline unsigned short muxbus_read_data(void)
{
   unsigned int data = 0, bit;
   int n;
          
   for(bit=1, n=0; n < 16; n++) {
      if (gpio_get_value(muxbus_gpio_pins[n].gpio)) 
         data |= bit;
      bit <<=1;
   }  
   return (unsigned short)data;
}

static inline void muxbus_write_data(unsigned short data)
{
   int n;
   for(n=0; n < 16; n++) {
      gpio_direction_output(muxbus_gpio_pins[n].gpio, data & 1);
      data >>=1;      
   }   
}

static inline int muxbus_wait_status(void)
{
   return gpio_get_value(MUXBUS_WAITN_GPIO);
}

static inline void muxbus_address(unsigned long address)
{
   int n;
      
   for(n=0; n < 16; n++) {
      gpio_direction_output(muxbus_gpio_pins[n].gpio, address & 1);
      address >>=1;      
   }
}

static int muxbus_open(struct inode *inode, struct file *file)
{
   return 0;  
}

static int muxbus_release(struct inode *inode, struct file *file)
{
   return 0;  
}



static ssize_t muxbus_write(struct file *file, const char __user *userdata,
      size_t len, loff_t *ppos)
{
   unsigned long flags;
   unsigned short data = 0;
   size_t n;
          
   n = MIN(2, len);
   if (copy_from_user(&data, userdata, n)) {
      return -EFAULT;  
   }         
      
   if (*ppos >= 0x400)
      return 0;

   local_irq_save(flags);

   if (n == 2) {
      if (*ppos & 1) {  
         data<<=8;
         n=1;
      }
      muxbus_bhe(0);
   } else if (*ppos & 1) {
         data<<=8;
      muxbus_bhe(0);
   } else
      muxbus_bhe(0);
         
   muxbus_dir(0);
   muxbus_bhe(0);      
   muxbus_ale(0);    /* assert ALE# */
   muxbus_address(*ppos);   
   /* ALE width */
   muxbus_ale(1);    /* deassert ALE# */
   /* address hold time */
   muxbus_write_data(data);   /* put data on A/D bus */
   muxbus_cs0(0);    /* assert CS0# */
   /* CS# width */
   muxbus_cs0(1);    /* deassert CS0# */
   muxbus_bhe(1);
   muxbus_dir(1);
   muxbus_data();    /* return A/D bus to inputs */
   
   local_irq_restore(flags);
            
   *ppos+=n;
   return n;
}

static ssize_t muxbus_read(struct file *file, char __user *buf,
		 size_t len, loff_t *off)
{   
   unsigned long flags;
   unsigned short data;
   size_t n;
   volatile int t;
      
   if (*off >= 0x400)
      return 0;

   n = MIN(2, len);
   
   local_irq_save(flags);

   muxbus_dir(1);
      
   if (n == 2)
      muxbus_bhe(0);
   else
      muxbus_bhe(1);

   muxbus_address(*off);   /* assert address */
   muxbus_ale(0);    /* assert ALE# */      
   /* ALE width */   
   muxbus_ale(1);    /* deassert ALE# */
   /* address hold time */
   muxbus_data();
   muxbus_cs0(0);    /* assert CS0# */
   t = 10;
   while(t--);
   t = 10000;
   while(! muxbus_wait_status()) {
      if (! t--) {
         local_irq_restore(flags);
         printk("muxbus timeout\n");
         return -EFAULT;
      }
   }
   
   data = muxbus_read_data();
   muxbus_cs0(1);    /* deassert CS0# */
   muxbus_bhe(1);    /* deassert BHE# */
      
   local_irq_restore(flags);
   
   if (n==1 && (*off & 1))
      data>>=8;
   
   if (copy_to_user(buf, &data, n)) {
      return -EFAULT;  
   }
   
   *off+=n;
   return n;
}


loff_t muxbus_llseek(struct file *filp, loff_t off, int whence)
{    
    loff_t newpos;

    switch(whence) {
      case 0: /* SEEK_SET */
        newpos = off;
        break;

      case 1: /* SEEK_CUR */
        newpos = filp->f_pos + off;
        break;

      case 2: /* SEEK_END */
        newpos = 0x3ff + off;
        break;

      default: /* can't happen */
        return -EINVAL;
    }
    if (newpos < 0 || newpos > 0x3ff) return -EINVAL;
    filp->f_pos = newpos;
    return newpos;
}


const struct file_operations muxbus_fops = {
   .owner =		THIS_MODULE,
	.read  = muxbus_read,
	.write = muxbus_write,
	.open =			muxbus_open,
	.llseek =			muxbus_llseek,
	.release =		muxbus_release,	
};



static struct platform_driver muxbus_driver = {
	.driver = {
		.name = "muxbus",
		.owner = THIS_MODULE,
	},	
};

static int __init muxbus_init(void)
{  
   int err, major, minor, devno;
    
   void __iomem *iomux_reg = MX6Q_IO_ADDRESS(MX6Q_IOMUXC_BASE_ADDR);
        
   err = alloc_chrdev_region(&muxbus_dev.dev, 0,
						4, muxbus_driver.driver.name);
	if (!err) {
	   major = MAJOR(muxbus_dev.dev);
		minor = MINOR(muxbus_dev.dev);
		
		devno = MKDEV(major, minor + 1);
		
		cdev_init(&muxbus_dev.cdev, &muxbus_fops);
		muxbus_dev.cdev.owner = THIS_MODULE;
		muxbus_dev.cdev.ops = &muxbus_fops;
      err = cdev_add(&muxbus_dev.cdev, devno, 1);
	
      if (err) {
         printk("Error: cdev_add failed in %s\n", __func__);
         return err;
      } else {
         printk("muxbus driver, %d.%d\n", major, minor);  
      }
	} else {
	    printk("Error: alloc_chrdev_region failed in %s\n", __func__);
	    return err;
	}
		
	
	/* setup drive strengths */
	if (cpu_is_imx6q()) {   
	   
 	   writel(0xa0f9, iomux_reg + 0x40C);  /* EIM_CS0 */
 	   writel(0xa0f9, iomux_reg + 0x418);  /* EIM_RW  */
 	   writel(0xa0f9, iomux_reg + 0x41C);  /* EIM_LBA */
 	   writel(0xa0f9, iomux_reg + 0x3E4);  /* EIM_D31 */
 	   writel(0xa0f9, iomux_reg + 0x428);  /* EIM_AD0 */
 	   writel(0xa0f9, iomux_reg + 0x42C);
 	   writel(0xa0f9, iomux_reg + 0x430);
 	   writel(0xa0f9, iomux_reg + 0x434);
 	   writel(0xa0f9, iomux_reg + 0x438);
 	   writel(0xa0f9, iomux_reg + 0x43C);
 	   writel(0xa0f9, iomux_reg + 0x440);
 	   writel(0xa0f9, iomux_reg + 0x444);
 	   writel(0xa0f9, iomux_reg + 0x448);
 	   writel(0xa0f9, iomux_reg + 0x44C);
 	   writel(0xa0f9, iomux_reg + 0x450);
 	   writel(0xa0f9, iomux_reg + 0x454);
 	   writel(0xa0f9, iomux_reg + 0x458);
 	   writel(0xa0f9, iomux_reg + 0x45C);
 	   writel(0xa0f9, iomux_reg + 0x460);
 	   writel(0xb0f9, iomux_reg + 0x464);  /* EIM_AD15 */
 	   writel(0xa0f9, iomux_reg + 0x468);  /* EIM_WAIT */
 	   
 	} else {
 	   writel(0xE0F9, iomux_reg + 0x50C);  /* EIM_CS0 */
 	   writel(0xE0F9, iomux_reg + 0x5AC);  /* EIM_RW  */
 	   writel(0xE0F9, iomux_reg + 0x5A4);  /* EIM_LBA */
 	   writel(0xE0F9, iomux_reg + 0x550);  /* EIM_D31 */
 	   writel(0xE0F9, iomux_reg + 0x554);  /* EIM_AD0 */
 	   writel(0xE0F9, iomux_reg + 0x558);  
 	   writel(0xE0F9, iomux_reg + 0x574);  
 	   writel(0xE0F9, iomux_reg + 0x578);  
 	   writel(0xE0F9, iomux_reg + 0x57C);  
 	   writel(0xE0F9, iomux_reg + 0x580);  
 	   writel(0xE0F9, iomux_reg + 0x584);  
 	   writel(0xE0F9, iomux_reg + 0x588);  
 	   writel(0xE0F9, iomux_reg + 0x58C);  
 	   writel(0xE0F9, iomux_reg + 0x590);  
 	   writel(0xE0F9, iomux_reg + 0x55C);  
 	   writel(0xE0F9, iomux_reg + 0x560);  
 	   writel(0xE0F9, iomux_reg + 0x564);  
 	   writel(0xE0F9, iomux_reg + 0x568);  
 	   writel(0xE0F9, iomux_reg + 0x56C);  
 	   writel(0xE0F9, iomux_reg + 0x570);  /* EIM_AD15 */
 	   writel(0xE0F9, iomux_reg + 0x5B0);  /* EIM_WAIT */
 	}

   err = gpio_request_array(muxbus_gpio_pins, ARRAY_SIZE(muxbus_gpio_pins));
			
	if (err)
	   goto error_out;

	muxbus_cs0(1);
	muxbus_bhe(1);
	muxbus_ale(1);
	muxbus_dir(1);
   		
	return 0;
	
error_out:
	return -ENOMEM;	
}

static void __exit muxbus_exit(void)
{
   cdev_del(&muxbus_dev.cdev);
   unregister_chrdev_region(muxbus_dev.dev, 4);
   
   gpio_free_array(muxbus_gpio_pins, ARRAY_SIZE(muxbus_gpio_pins));
   
}

subsys_initcall(muxbus_init);
module_exit(muxbus_exit);
MODULE_AUTHOR("Ian <ian@embeddedarm.com>");
MODULE_DESCRIPTION("TS MUXBUS Driver");
MODULE_ALIAS("TS-MUXBUS driver");
MODULE_LICENSE("GPL v2");
