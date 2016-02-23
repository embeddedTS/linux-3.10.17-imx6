#ifndef _TS_GPIO_H_
#define _TS_GPIO_H_

#define TSGPIO_OE      0x0001
#define TSGPIO_OD      0x0002
#define TSGPIO_ID      0x0004

struct tsgpio_platform_data {
	int base;
	int twobit;
	int ngpio;
};

#endif /* _TS_GPIO_H_ */
