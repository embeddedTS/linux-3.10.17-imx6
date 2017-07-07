#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/spi/spi.h>

#include "linux_wlan_common.h"
#include "at_pwr_dev.h"

#define USE_SPI_DMA     0

struct wilc_wlan_os_context  g_linux_spi_os_context;
struct spi_device *wilc_spi_dev;
EXPORT_SYMBOL(wilc_spi_dev);

void chip_wakeup(int source);
void chip_allow_sleep(int source);
extern void (*pf_chip_sleep_manually)(unsigned int , int );
extern int (*pf_get_num_conn_ifcs)(void);
extern void (*pf_host_wakeup_notify)(int);
extern void (*pf_host_sleep_notify)(int);
extern int (*pf_get_u8SuspendOnEvent_value)(void);



static int wilc_bus_probe(struct spi_device* spi)
{
	PRINT_D(INIT_DBG, "spiModalias: %s, spiMax-Speed: %d\n", 
		spi->modalias, spi->max_speed_hz);
	wilc_spi_dev = spi;

	up(&spi_probe_sync);
	return 0;
}

static int wilc_bus_remove(struct spi_device *spi)
{
	return 0;
}

static int wilc_spi_suspend(struct device *dev)
{
	printk("\n\n << SUSPEND >>\n\n");
	if((g_linux_spi_os_context.hif_critical_section) != NULL)
		mutex_lock((struct mutex*)(g_linux_spi_os_context.hif_critical_section));
	chip_wakeup(0);
	if((g_linux_spi_os_context.hif_critical_section)!= NULL){
		if (mutex_is_locked((struct mutex*)(g_linux_spi_os_context.hif_critical_section))){
			mutex_unlock((struct mutex*)(g_linux_spi_os_context.hif_critical_section));
		}
	}
	/*if there is no events , put the chip in low power mode */
	if(pf_get_u8SuspendOnEvent_value()== 0){
		/*BugID_5213*/
		/*Allow chip sleep, only if both interfaces are not connected*/
		if(!pf_get_num_conn_ifcs())
			pf_chip_sleep_manually(0xFFFFFFFF,0);
	}
	else{
		/*notify the chip that host will sleep*/
		pf_host_sleep_notify(0);
		chip_allow_sleep(0);
	}
	if((g_linux_spi_os_context.hif_critical_section) != NULL)
		mutex_lock((struct mutex*)(g_linux_spi_os_context.hif_critical_section));

 	return 0 ;
}

static int wilc_spi_resume(struct device *dev)
{
	printk("\n\n  <<RESUME>> \n\n");
	
	/*wake the chip to compelete the re-intialization*/
	chip_wakeup(0);

	if((g_linux_spi_os_context.hif_critical_section)!= NULL){
		if (mutex_is_locked((struct mutex*)(g_linux_spi_os_context.hif_critical_section))){
			mutex_unlock((struct mutex*)(g_linux_spi_os_context.hif_critical_section));
		}
	}

	if(pf_get_u8SuspendOnEvent_value()== 1)
		pf_host_wakeup_notify(0);
	
	if((g_linux_spi_os_context.hif_critical_section) != NULL)
		mutex_lock((struct mutex*)(g_linux_spi_os_context.hif_critical_section));
		
	chip_allow_sleep(0);
	
	if((g_linux_spi_os_context.hif_critical_section)!= NULL){
		if (mutex_is_locked((struct mutex*)(g_linux_spi_os_context.hif_critical_section))){
			mutex_unlock((struct mutex*)(g_linux_spi_os_context.hif_critical_section));
		}
	}

	return 0;
}
#ifdef CONFIG_OF
static const struct of_device_id wilc_of_match[] = {
	{ .compatible = "atmel,wilc_spi", },
	{}
};
MODULE_DEVICE_TABLE(of, wilc_of_match);
#endif

static const struct dev_pm_ops wilc_spi_pm_ops = {	
     .suspend = wilc_spi_suspend,    
     .resume    = wilc_spi_resume,
    	};

struct spi_driver wilc_bus __refdata = {
	.driver = {
		.name = MODALIAS,
#ifdef CONFIG_OF
		.of_match_table = wilc_of_match,
#endif
		.pm = &wilc_spi_pm_ops,
	},
	.probe =  wilc_bus_probe,
	.remove = __exit_p(wilc_bus_remove),
};

void linux_spi_deinit(void* vp){
	spi_unregister_driver(&wilc_bus);	
}

int linux_spi_init(void* vp){
	int ret = 1;
	static int called = 0;
	
	if(called == 0){
		called++;
		ret = spi_register_driver(&wilc_bus);		
	}
	memcpy(&g_linux_spi_os_context,(struct wilc_wlan_os_context*) vp,sizeof(struct wilc_wlan_os_context));

	(ret<0)? (ret = 0):(ret = 1);
	
	return ret;
}

int linux_spi_write(u8 *b, uint32_t len)
{	

	int ret;
	struct spi_message msg;

	if (len > 0 && NULL != b) {
		struct spi_transfer tr = {
			.tx_buf = b,
			.len = len,
			.delay_usecs = 0,
		};
		char *r_buffer = (char*) kzalloc(len, GFP_KERNEL);
		if(! r_buffer){
			PRINT_ER("Failed to allocate memory for r_buffer\n");
			return -1;
		}
		tr.rx_buf = r_buffer;
		PRINT_D(BUS_DBG, "Request writing %d bytes\n", len);

		memset(&msg, 0, sizeof(msg));
		spi_message_init(&msg);
		spi_message_add_tail(&tr, &msg);
		
		ret = spi_sync(wilc_spi_dev, &msg);
		if(ret < 0)
			PRINT_ER( "SPI transaction failed\n");

		kfree(r_buffer);
	} else {
		PRINT_ER("can't write data with the following length: %d, or NULL buffer\n",len);
		ret = -1;
	}

	(ret < 0) ? (ret = 0) : (ret = 1);

	return ret;
}

int linux_spi_read(u8 *rb, uint32_t rlen)
{
	int ret;
	
	if(rlen > 0){
		struct spi_message msg;
		struct spi_transfer tr = {
		//		.tx_buf = t_buffer,
				.rx_buf = rb,
				.len = rlen,
				.delay_usecs = 0,

		};
		char *t_buffer = (char*) kzalloc(rlen, GFP_KERNEL);
		if(! t_buffer){
			PRINT_ER("Failed to allocate memory for t_buffer\n");
			return -1;
		}
		tr.tx_buf = t_buffer;			

		memset(&msg, 0, sizeof(msg));
		spi_message_init(&msg);

		msg.spi = wilc_spi_dev;
		msg.is_dma_mapped = USE_SPI_DMA;

		spi_message_add_tail(&tr,&msg);

		ret = spi_sync(wilc_spi_dev,&msg);
		if(ret < 0)
			PRINT_ER("SPI transaction failed\n");
		/*	
		else {
		   int i;
		   for(i=0; i < rlen; i++)
		      printk("%02X ", rb[i]);
		}
		*/
		kfree(t_buffer);
	}else{
		PRINT_ER("can't read data with the following length: %d\n",rlen);
		ret = -1;
	}
	(ret<0)? (ret = 0):(ret = 1);

	return ret;
}

int linux_spi_write_read(u8 *wb, u8 *rb, unsigned int rlen)
{
	int ret;

	if(rlen > 0) {
		struct spi_message msg;
		struct spi_transfer tr = {
			.rx_buf = rb,
			.tx_buf = wb,
			.len = rlen,
			.bits_per_word = 8,
			.delay_usecs = 0,

		};

		memset(&msg, 0, sizeof(msg));
		spi_message_init(&msg);
		msg.spi = wilc_spi_dev;
		msg.is_dma_mapped = USE_SPI_DMA;
		
		spi_message_add_tail(&tr,&msg);
		ret = spi_sync(wilc_spi_dev,&msg);
		if(ret < 0)
			PRINT_ER("SPI transaction failed\n");
	}else{
		PRINT_ER("can't read data with the following length: %d\n",rlen);
		ret = -1;
	}
	(ret<0)? (ret = 0):(ret = 1);

	return ret;
}

