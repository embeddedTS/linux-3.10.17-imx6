
/*!  
*  @file		wilc_gpio.c
*  @author	
*  
*/


/*****************************************************************************/
/* File Includes                                                             */
/*****************************************************************************/
#include "wilc_gpio.h"

/*****************************************************************************/
/*                                                                           */
/*  Function Name    : wilc_gpio_init                                             */
/*                                                                           */
/*  Description      : This function allocates a gpio from the host    */
/*                                                                           */
/*  Inputs           : 1) gpio_num: this number is a mapped number to the hardware port pin,   */
/*							you can find the mapping in "wilc_gpio.h" file */
/*                     2) gpio_direction: one of the values "GPIO_IN , GPIO_OUT"  in the enum in "wilc_gpio.h"    */
/*                     3) label: write any string to be linked to the gpio , has no use here */
/*                                                                           */
/*  Globals          : None                                                  */
/*  Processing       : None                                                  */
/*  Outputs          : None                                                  */
/*  Returns          : None                                                  */
/*  Issues           : None                                                  */
/*                                                                           */
/*****************************************************************************/

void wilc_gpio_init(int gpio_num, char direction, char *label)
{
	if (gpio_request(gpio_num, label) == 0)
	{
		if(direction == GPIO_IN)
		{
			gpio_direction_input(gpio_num);
		}
		else if (direction == GPIO_OUT)
		{
			gpio_direction_output(gpio_num, 0);
		}
	}
	else
		printk("Couldn't allocate GPIO %d\n",gpio_num);
}


void wilc_gpio_set_direction(int gpio_num, char direction)
{
	if(direction == GPIO_IN)
	{
		gpio_direction_input(gpio_num);
	}
	else if (direction == GPIO_OUT)
	{
		gpio_direction_output(gpio_num, 0);
	}
	else
		printk("enter a valid direction value\n");
}
char wilc_gpio_get_val(int gpio_num)
{
	return gpio_get_value(gpio_num);
}


void wilc_gpio_set_val(int gpio_num, char val)
{
	gpio_set_value(gpio_num , val);
}

void wilc_gpio_free(int gpio_num)
{
	gpio_free(gpio_num);
}
 
