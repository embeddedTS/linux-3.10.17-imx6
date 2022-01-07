#include <linux/module.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/kthread.h>
#include <linux/irq.h>
#include <linux/gpio.h>
#include <linux/platform_device.h>
#include <linux/of.h>
#include <linux/of_gpio.h>
#include <linux/of_device.h>
#include <linux/i2c.h>
#include <linux/i2c/ts4900gpio.h>

/* See register documentation at 
 * http://wiki.embeddedTS.com/wiki/TS-4900#FPGA
 */

struct gpio_ts4900_priv {
	struct i2c_client *client;
	struct gpio_chip gpio_chip;
	struct mutex mutex;
};

static inline struct gpio_ts4900_priv *to_gpio_ts4900(struct gpio_chip *chip)
{
	return container_of(chip, struct gpio_ts4900_priv, gpio_chip);
}

/*
 * To configure ts4900 GPIO module registers
 */
static inline int gpio_ts4900_write(struct i2c_client *client, u16 addr, u8 data)
{
	u8 out[3];
	int ret;
	struct i2c_msg msg;

	out[0] = ((addr >> 8) & 0xff);
	out[1] = (addr & 0xff);
	out[2] = data;

	msg.addr = client->addr;
	msg.flags = 0;
	msg.len = 3;
	msg.buf = out;

	dev_dbg(&client->dev, "%s Writing 0x%X to 0x%X\n", __func__, data, addr);

	ret = i2c_transfer(client->adapter, &msg, 1);
	if (ret != 1) {
		dev_err(&client->dev, "%s: write error, ret=%d\n",
			__func__, ret);
		return -EIO;
	}

	return ret;
}

/*
 * To read a ts4900 GPIO module register
 */
static inline int gpio_ts4900_read(struct i2c_client *client, u16 addr)
{
	u8 data[3];
	int ret;
	struct i2c_msg msgs[2];

	data[0] = ((addr >> 8) & 0xff);
	data[1] = (addr & 0xff);
	data[2] = 0;

	msgs[0].addr = client->addr;
	msgs[0].flags = 0;
	msgs[0].len	= 2;
	msgs[0].buf	= data;

	msgs[1].addr = client->addr;
	msgs[1].flags = I2C_M_RD;
	msgs[1].len	= 1;
	msgs[1].buf	= data;

	ret = i2c_transfer(client->adapter, msgs, ARRAY_SIZE(msgs));
	if (ret != ARRAY_SIZE(msgs)) {
		dev_err(&client->dev, "%s: read error, ret=%d\n",
			__func__, ret);
		return -EIO;
	}
	dev_dbg(&client->dev, "%s read 0x%X from 0x%X\n", __func__, data[0], addr);

	return data[0];
}

static int ts4900_set_gpio_direction(struct i2c_client *client,
	int gpio, int is_input)
{
	u8 reg;

	dev_dbg(&client->dev, "%s setting gpio %d to is_input=%d\n", 
		__func__, gpio, is_input);

	reg = gpio_ts4900_read(client, gpio);
	
	if(is_input) reg &= 0x6;
	else reg |= 0x1;

	gpio_ts4900_write(client, gpio, reg);

	return 0;
}

static int ts4900_set_gpio_dataout(struct i2c_client *client, int gpio, int enable)
{
	u8 reg;

	dev_dbg(&client->dev, "%s setting gpio %d to output=%d\n", 
		__func__, gpio, enable);

	reg = gpio_ts4900_read(client, gpio);
	
	if(enable) reg |= 0x2;
	else reg &= 0x5;

	return gpio_ts4900_write(client, gpio, reg);
}

static int ts4900_get_gpio_datain(struct i2c_client *client, int gpio)
{
	u8 reg, addr;
	
	dev_dbg(&client->dev, "%s Getting GPIO %d Input\n", __func__, gpio);

	addr = gpio;
	if(gpio > 12) gpio += 44;

	reg = gpio_ts4900_read(client, addr);

	return ((reg & 0x4) ? 1 : 0);
}

static int ts_direction_in(struct gpio_chip *chip, unsigned offset)
{
	struct gpio_ts4900_priv *priv = to_gpio_ts4900(chip);
	int ret;

	mutex_lock(&priv->mutex);
	ret = ts4900_set_gpio_direction(priv->client, offset, 1);
	mutex_unlock(&priv->mutex);

	return ret;
}

static int ts_get(struct gpio_chip *chip, unsigned offset)
{
	struct gpio_ts4900_priv *priv = to_gpio_ts4900(chip);
	int status;

	mutex_lock(&priv->mutex);
	status = ts4900_get_gpio_datain(priv->client, offset);
	mutex_unlock(&priv->mutex);
	return status;
}

static void ts_set(struct gpio_chip *chip, unsigned offset, int value)
{
	struct gpio_ts4900_priv *priv = to_gpio_ts4900(chip);

	mutex_lock(&priv->mutex);
	ts4900_set_gpio_dataout(priv->client, offset, value);
	mutex_unlock(&priv->mutex);
}

static int ts_direction_out(struct gpio_chip *chip, unsigned offset, int value)
{
	struct gpio_ts4900_priv *priv = to_gpio_ts4900(chip);

	mutex_lock(&priv->mutex);
	ts4900_set_gpio_dataout(priv->client, offset, value);
	ts4900_set_gpio_direction(priv->client, offset, 0);
	mutex_unlock(&priv->mutex);

	return 0;
}

static struct gpio_chip template_chip = {
	.label			= "ts4900gpio",
	.owner			= THIS_MODULE,
	.request		= NULL,
	.free			= NULL,
	.direction_input	= ts_direction_in,
	.get			= ts_get,
	.direction_output	= ts_direction_out,
	.set			= ts_set,
	.to_irq			= NULL,
	.can_sleep		= 1,
};

static int gpio_ts4900_remove(struct i2c_client *client)
{
	struct gpio_ts4900_priv *priv = 
		(struct gpio_ts4900_priv *)i2c_get_clientdata(client);
	int status;

	status = gpiochip_remove(&priv->gpio_chip);
	if (status < 0)
		return status;

	return 0;
}

#ifdef CONFIG_OF
static const struct of_device_id ts4900gpio_ids[] = {
        { .compatible = "ts4900gpio", },
        {},
};

MODULE_DEVICE_TABLE(of, ts4900gpio_ids);

static const struct ts4900gpio_platform_data *ts4900gpio_probe_dt(struct device *dev)
{
	struct ts4900gpio_platform_data *pdata;
	struct device_node *node = dev->of_node;
	const struct of_device_id *match;

	if (!node) {
		dev_err(dev, "Device does not have associated DT data\n");
		return ERR_PTR(-EINVAL);
	}

	match = of_match_device(ts4900gpio_ids, dev);
	if (!match) {
		dev_err(dev, "Unknown device model\n");
		return ERR_PTR(-EINVAL);
	}

	pdata = devm_kzalloc(dev, sizeof(*pdata), GFP_KERNEL);
	if (!pdata)
		return ERR_PTR(-ENOMEM);

	pdata->bbclk12 = of_property_read_bool(node, "bbclk12");
	pdata->bbclk14 = of_property_read_bool(node, "bbclk14");
	pdata->bbclk24 = of_property_read_bool(node, "bbclk24");
	pdata->uart2en = of_property_read_bool(node, "uart2en");
	pdata->uart4en = of_property_read_bool(node, "uart4en");

	return pdata;
}
#else
static const struct ts4900gpio_platform_data *ts4900gpio_probe_dt(struct device *dev)
{
	dev_err(dev, "no platform data defined\n");
	return ERR_PTR(-EINVAL);
}
#endif

static int gpio_ts4900_probe(struct i2c_client *client,
                         const struct i2c_device_id *id)
{
	struct gpio_ts4900_priv *priv;
	const struct ts4900gpio_platform_data *pdata;

	int ret;

	if (!i2c_check_functionality(client->adapter,
		I2C_FUNC_SMBUS_BYTE_DATA))
		return -EIO;

	pdata = dev_get_platdata(&client->dev);
	if (!pdata) {
		pdata = ts4900gpio_probe_dt(&client->dev);
		if (IS_ERR(pdata))
			return PTR_ERR(pdata);
	}

	priv = devm_kzalloc(&client->dev, sizeof(struct gpio_ts4900_priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	i2c_set_clientdata(client, priv);
	priv->client = client;
	priv->gpio_chip = template_chip;
	priv->gpio_chip.base = -1;
	priv->gpio_chip.ngpio = 32;
	priv->gpio_chip.dev = &client->dev;

	mutex_init(&priv->mutex);

	ret = gpiochip_add(&priv->gpio_chip);
	if (ret < 0) {
		dev_err(&client->dev, "could not register gpiochip, %d\n", ret);
		priv->gpio_chip.ngpio = 0;
	}
	if(pdata->bbclk12) {
		printk(KERN_INFO "Enabling 12MHz baseboard clock on CN1-87\n");
		gpio_ts4900_write(client, 47, 0x1);
	}
	if(pdata->bbclk14) {
		printk(KERN_INFO "Enabling 14.3MHz baseboard clock on CN1-87\n");
		gpio_ts4900_write(client, 48, 0x1);	
	} 
	if(pdata->bbclk24) {
		printk(KERN_ERR "Enabling 24MHz baseboard clock on CN1-87\n");
		gpio_ts4900_write(client, 47, 0x1);
		gpio_ts4900_write(client, 52, 0x1);
	} 
	if(pdata->uart2en) {
		printk(KERN_INFO "Mapping ttymxc1 to CN2-78/CN2-80\n");
		gpio_ts4900_write(client, 49, 0x1);
	}
	if(pdata->uart4en){
		printk(KERN_INFO "Mapping ttymxc3 to CN2-86/CN2-88\n");
		gpio_ts4900_write(client, 50, 0x1);
	} 

	return ret;
}

static const struct i2c_device_id ts4900gpio_id[] = {
	{ "ts4900gpio", 0 },
	{ }
};
MODULE_DEVICE_TABLE(i2c, ts4900gpio_id);

MODULE_ALIAS("platform:ts4900gpio");

static struct i2c_driver gpio_ts4900_driver = {
	.driver = {
		.name	= "ts4900gpio",
		.owner	= THIS_MODULE,
#ifdef CONFIG_OF
		.of_match_table = of_match_ptr(ts4900gpio_ids),
#endif
	},
	.probe		= gpio_ts4900_probe,
	.remove		= gpio_ts4900_remove,
	.id_table 	= ts4900gpio_id,
};

static int __init gpio_ts4900_init(void)
{
	return i2c_add_driver(&gpio_ts4900_driver);
}
subsys_initcall(gpio_ts4900_init);

static void __exit gpio_ts4900_exit(void)
{
	i2c_del_driver(&gpio_ts4900_driver);
}
module_exit(gpio_ts4900_exit);

MODULE_AUTHOR("embeddedTS");
MODULE_DESCRIPTION("GPIO interface for ts4900");
MODULE_LICENSE("GPL");
