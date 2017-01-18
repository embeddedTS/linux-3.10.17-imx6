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

#ifdef CONFIG_OF
static const struct of_device_id wilc_of_match[] = {
	{ .compatible = "atmel,wilc_spi", },
	{}
};
MODULE_DEVICE_TABLE(of, wilc_of_match);
#endif

struct spi_driver wilc_bus __refdata = {
	.driver = {
		.name = MODALIAS,
#ifdef CONFIG_OF
		.of_match_table = wilc_of_match,
#endif
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

