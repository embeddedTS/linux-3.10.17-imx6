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
#include <linux/i2c/tsgpio.h>

struct gpio_ts_priv {
	struct i2c_client *client;
	struct gpio_chip gpio_chip;
	struct mutex mutex;
};

static inline struct gpio_ts_priv *to_gpio_ts(struct gpio_chip *chip)
{
	return container_of(chip, struct gpio_ts_priv, gpio_chip);
}

/*
 * To configure ts GPIO module registers
 */
static inline int gpio_ts_write(struct i2c_client *client, u16 addr, u8 data)
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

	dev_dbg(&client->dev, "%s Writing 0x%X to 0x%X\n",
		__func__,
		data,
		addr);

	ret = i2c_transfer(client->adapter, &msg, 1);
	if (ret != 1) {
		dev_err(&client->dev, "%s: write error, ret=%d\n",
			__func__, ret);
		return -EIO;
	}

	return ret;
}

/*
 * To read a ts GPIO module register
 */
static inline int gpio_ts_read(struct i2c_client *client, u16 addr)
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
	dev_dbg(&client->dev, "%s read 0x%X from 0x%X\n",
		__func__,
		data[0],
		addr);

	return data[0];
}

static int ts_set_gpio_input(struct i2c_client *client,
	int gpio)
{
	dev_dbg(&client->dev, "%s setting gpio %d to input\n",
		__func__,
		gpio);

	/* This will clear the data enable, the other bits are
	 * dontcare when this is cleared
	 */
	gpio_ts_write(client, gpio, 0);

	return 0;
}

static int ts_set_gpio_dataout(struct i2c_client *client, int gpio, int enable)
{
	u8 reg = 0x0;

	dev_dbg(&client->dev, "%s setting gpio %d to output=%d\n",
		__func__,
		gpio,
		enable);

	if (enable)
		reg = TSGPIO_OD | TSGPIO_OE;
	else
		reg = TSGPIO_OE;

	return gpio_ts_write(client, gpio, reg);
}

static int ts_get_gpio_datain(struct i2c_client *client, int gpio)
{
	struct tsgpio_platform_data *pdata = client->dev.platform_data;
	u8 reg;
	int ret;

	dev_dbg(&client->dev, "%s Getting GPIO %d Input\n", __func__, gpio);

	reg = gpio_ts_read(client, gpio);

	if (pdata->twobit)
		ret = (reg & TSGPIO_OD) ? 1 : 0;
	else
		ret = (reg & TSGPIO_ID) ? 1 : 0;

	return ret;
}

static int ts_direction_in(struct gpio_chip *chip, unsigned offset)
{
	struct gpio_ts_priv *priv = to_gpio_ts(chip);
	int ret;

	mutex_lock(&priv->mutex);
	ret = ts_set_gpio_input(priv->client, offset);
	mutex_unlock(&priv->mutex);

	return ret;
}

static int ts_get(struct gpio_chip *chip, unsigned offset)
{
	struct gpio_ts_priv *priv = to_gpio_ts(chip);
	int status;

	mutex_lock(&priv->mutex);
	status = ts_get_gpio_datain(priv->client, offset);
	mutex_unlock(&priv->mutex);
	return status;
}

static void ts_set(struct gpio_chip *chip, unsigned offset, int value)
{
	struct gpio_ts_priv *priv = to_gpio_ts(chip);

	mutex_lock(&priv->mutex);
	ts_set_gpio_dataout(priv->client, offset, value);
	mutex_unlock(&priv->mutex);
}

static int ts_direction_out(struct gpio_chip *chip, unsigned offset, int value)
{
	struct gpio_ts_priv *priv = to_gpio_ts(chip);

	mutex_lock(&priv->mutex);
	ts_set_gpio_dataout(priv->client, offset, value);
	mutex_unlock(&priv->mutex);

	return 0;
}

static struct gpio_chip template_chip = {
	.label			= "tsgpio",
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

#ifdef CONFIG_OF
static const struct of_device_id tsgpio_ids[] = {
	{ .compatible = "technologic,tsgpio", .data = (void *) 0},
	{ .compatible = "technologic,tsgpio-2bitio", .data = (void *) 1},
	{},
};

MODULE_DEVICE_TABLE(of, tsgpio_ids);

static struct tsgpio_platform_data *tsgpio_probe_dt(struct device *dev)
{
	struct tsgpio_platform_data *pdata;
	struct device_node *node = dev->of_node;
	const struct of_device_id *match;

	if (!node) {
		dev_err(dev, "Device does not have associated DT data\n");
		return ERR_PTR(-EINVAL);
	}

	match = of_match_device(tsgpio_ids, dev);
	if (!match) {
		dev_err(dev, "Unknown device model\n");
		return ERR_PTR(-EINVAL);
	}

	pdata = devm_kzalloc(dev, sizeof(*pdata), GFP_KERNEL);
	if (!pdata)
		return ERR_PTR(-ENOMEM);

	pdata->twobit = (unsigned long)match->data;

	if (of_property_read_u32(node, "base", &pdata->base))
		return ERR_PTR(-EINVAL);

	if (of_property_read_u16(node, "ngpio", &pdata->ngpio))
		return ERR_PTR(-EINVAL);

	return pdata;
}
#else
static struct tsgpio_platform_data *tsgpio_probe_dt(struct device *dev)
{
	dev_err(dev, "no platform data defined\n");
	return ERR_PTR(-EINVAL);
}
#endif

static int gpio_ts_probe(struct i2c_client *client,
	const struct i2c_device_id *id)
{
	struct gpio_ts_priv *priv;
	struct tsgpio_platform_data *pdata;

	int ret;

	if (!i2c_check_functionality(client->adapter,
		I2C_FUNC_SMBUS_BYTE_DATA))
		return -EIO;

	pdata = dev_get_platdata(&client->dev);
	if (!pdata) {
		pdata = tsgpio_probe_dt(&client->dev);
		if (IS_ERR(pdata))
			return PTR_ERR(pdata);
	}
	client->dev.platform_data = pdata;

	priv = devm_kzalloc(&client->dev,
		sizeof(struct gpio_ts_priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	i2c_set_clientdata(client, priv);
	priv->client = client;
	priv->gpio_chip = template_chip;
	priv->gpio_chip.base = pdata->base;
	priv->gpio_chip.ngpio = pdata->ngpio;
	priv->gpio_chip.label = "tsgpio";
	priv->gpio_chip.dev = &client->dev;

	mutex_init(&priv->mutex);

	ret = gpiochip_add(&priv->gpio_chip);
	if (ret < 0) {
		dev_err(&client->dev, "could not register gpiochip, %d\n", ret);
		priv->gpio_chip.ngpio = 0;
	}

	return ret;
}

static const struct i2c_device_id tsgpio_id[] = {
	{ "tsgpio", 0 },
	{ }
};
MODULE_DEVICE_TABLE(i2c, tsgpio_id);

MODULE_ALIAS("i2c:tsgpio");

static struct i2c_driver gpio_ts_driver = {
	.driver = {
		.name	= "tsgpio",
		.owner	= THIS_MODULE,
#ifdef CONFIG_OF
		.of_match_table = of_match_ptr(tsgpio_ids),
#endif
	},
	.probe		= gpio_ts_probe,
	.id_table	= tsgpio_id,
};

static int __init gpio_ts_init(void)
{
	return i2c_add_driver(&gpio_ts_driver);
}
subsys_initcall(gpio_ts_init);

static void __exit gpio_ts_exit(void)
{
	i2c_del_driver(&gpio_ts_driver);
}
module_exit(gpio_ts_exit);

MODULE_AUTHOR("embeddedTS");
MODULE_DESCRIPTION("GPIO interface for embeddedTS I2C-FPGA core");
MODULE_LICENSE("GPL");
