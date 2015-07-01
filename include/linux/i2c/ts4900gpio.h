
#ifndef _TS4900_GPIO_H_
#define _TS4900_GPIO_H_

#define TSGPIO_OE	0x0001
#define TSGPIO_OD	0x0002 
#define TSGPIO_ID	0x0004

struct ts4900gpio_platform_data {
	int model;
	u32 bank;
};

#endif /* _TS4900_GPIO_H_ */
