  /*
 * Copyright 2017 Ayla Networks, Inc.  All rights reserved.
 */

/*
 * Ayla device agent demo of a simple lights and buttons evaluation board
 * using the "simple" property manager.
 *
 * The property names are chosen to be compatible with the Ayla Control
 * App.  E.g., the LED property is Blue_LED even though the color is yellow.
 * Button1 sends the Blue_button property, even though the button is white.
 */
#define HAVE_UTYPES
#include "lwip/ip_addr.h"

#include <ayla/utypes.h>
#include <ayla/log.h>
#include <sys/types.h>
#include <ada/libada.h>
#include <ada/sprop.h>
#include <ada/task_label.h>
#include "conf.h"
#include "demo.h"
#include "led_key.h"
#include "PinNames.h"


#define BUILD_PID         "SN0-8888888"  //设备名称+随机码
#define BUILD_PROGNAME    "smartplug"
#define BUILD_VERSION     "ASW-01"  //模组名称
#define BUILD_STRING	   BUILD_VERSION " "  "V001-01" " " __DATE__ " " __TIME__  //V001 是模版版本号  01是固件版本号

/*
 * The oem and oem_model strings determine the host name for the
 * Ayla device service and the device template on the service.
 *
 * If these are changed, the encrypted OEM secret must be re-encrypted
 * unless the oem_model was "*" (wild-card) when the oem_key was encrypted.
 */
char oem[] = DEMO_OEM_ID;
char oem_model[] = DEMO_LEDEVB_MODEL;

static u8 switch_control;
static unsigned blue_button;
static u8 blue_led;
static u8 green_led;
static int input;
static int output;
static int decimal_in;
static int decimal_out;

static char version[] =BUILD_PID " " BUILD_PROGNAME " " BUILD_STRING;   //固件软件version

static char cmd_buf[TLV_MAX_STR_LEN + 1];

static char demo_host_version[] = "V001";	/* property template version  模版版本*/

static enum ada_err demo_led_set(struct ada_sprop *, const void *, size_t);
static enum ada_err demo_int_set(struct ada_sprop *, const void *, size_t);
static enum ada_err demo_cmd_set(struct ada_sprop *, const void *, size_t);

void prop_send_by_name(const char *name);

//智能插座相关定义
#define STACKSIZE_LED                                      512      //指示灯任务栈大小
#define STACKSIZE_KEY                                      512      //按键任务栈大小

/* 定义 按键 IO PIN 及相关按下状态*/
#define key_state_0        0
#define key_state_1        1
#define key_state_2        2
#define key_state_3        3

#define key_no 	           0
#define key_click	       1
#define key_double	       2
#define key_long	       3
#define key_long_long      4


/* 定义 Key/LED/OPT IO PIN */
#define KEY_PIN_SET		                  PA_12  //设置按键
#define OPT_PIN                           PA_15   //继电器电源控制引脚
#define LED_PIN3                          PA_22  //wifi指示灯

/* 读取KEY值 */
#define KEY1_READ			              GPIO_ReadDataBit(KEY_PIN_SET)
/*读取继电器IO值*/
#define OPT_READ                          GPIO_ReadDataBit(OPT_PIN)

int time_bl=1000;                                //产测指示灯闪烁时间间隔

/* 函数声明*/
static unsigned char key_driver(void);

//led灯io相关操作
void Led_Indicate(void);
void led_thread(void *param);

//单色指示灯
void LED_SINGLE_Fast(void);
void LED_SINGLE_Slow(void);
void LED_SINGLE_LightOn(void);
void LED_SINGLE_LightOff(void);

//按键
void KEY_Indicate(void);
void key_thread(void);

//定义三个flag  工作模式、airkiss模式、ap模式，初始化为airkiss模式
int flag_work_mode=0;
int flag_airkiss_mode=1;
int flag_ap_mode=0;

//定义未连接上路由注册失败flag
int flag_connect_fail=0;
//定义手机端注册成功flag
int flag_register_ok=0;
//定义设备wifi down后的标志
int flag_device_down=0;

//定义产测模式进入标志位
int flag_join_success=0;
int flag_produce_mode=0;

//定义获取region标志位
int  flag_region_get=0;
int  flag_region_which=0;
static struct ada_sprop demo_props[] = {
	/*
	 * version properties
	 */
	{ "oem_host_version", ATLV_UTF8,
	    demo_host_version, sizeof(demo_host_version),
	    ada_sprop_get_string, NULL},
	{ "version", ATLV_UTF8, &version[0], sizeof(version),
	    ada_sprop_get_string, NULL},
	/*
	 * boolean properties
	 */
	 { "Switch_Control", ATLV_BOOL, &switch_control, sizeof(switch_control),
	    ada_sprop_get_bool, demo_led_set },
};
/*
 * Initialize property manager.
 */
void demo_init(void)
{
    ada_sprop_mgr_register("SN0-01-0-001", demo_props, ARRAY_LEN(demo_props));	
}

//单色指示灯快闪
void LED_SINGLE_Fast(void)
{
	GPIO_WriteBit(LED_PIN3, 1);
	vTaskDelay(150);
	GPIO_WriteBit(LED_PIN3, 0);
}
//单色指示灯慢闪
 void LED_SINGLE_Slow(void)
{
	GPIO_WriteBit(LED_PIN3, 0);
	vTaskDelay(700);
	GPIO_WriteBit(LED_PIN3, 1);
	vTaskDelay(700);
}
//单色灯常亮
void LED_SINGLE_LightOn(void)
{
	GPIO_WriteBit(LED_PIN3, 0);
}
//单色灯熄灭
void LED_SINGLE_LightOff(void)
{
	GPIO_WriteBit(LED_PIN3, 1);
}

//led指示灯执行函数
void led_thread(void *param)
{
        sys_jtag_off();
        init_led_key();
        for(;;){
            vTaskDelay(130);
            if(flag_airkiss_mode==1&&flag_work_mode==0&&flag_ap_mode==0&&flag_connect_fail==0) { LED_SINGLE_Fast();}
    	    if(flag_ap_mode==1&&flag_airkiss_mode==0&&flag_work_mode==0&&flag_connect_fail==0) {LED_SINGLE_Slow(); }
            if((flag_work_mode==1&&flag_ap_mode==0&&flag_airkiss_mode==0)||(flag_connect_fail==1)){LED_SINGLE_LightOff();}

            if(flag_produce_mode){ //产测模式路由器交替闪烁指示灯
                     GPIO_WriteBit(LED_PIN3, 1);
                     GPIO_WriteBit(OPT_PIN, 1);
	                 vTaskDelay(time_bl);
	                 GPIO_WriteBit(LED_PIN3, 0);
                     GPIO_WriteBit(OPT_PIN, 0);
	                 vTaskDelay(time_bl);
	          }
       }//end for
        vTaskDelete(NULL);
}
//建立led指示灯线程任务
void Led_Indicate()
{
  if(xTaskCreate(led_thread, ((const char*)"led_light"), STACKSIZE_LED, NULL, tskIDLE_PRIORITY + 1, NULL) != pdPASS)
		printf("\n\r%s xTaskCreate(Led_Indicate) failed", __FUNCTION__);
}

/***************************************************************************
程序功能：一个按键的单击、长按。
***************************************************************************/
static unsigned char key_driver(void)
{
	static unsigned char key_state_buffer1 = key_state_0;
	static unsigned char key_timer_cnt1 = 0;
	unsigned char key_return = key_no;
	unsigned char key;

	key = KEY1_READ;  //read the key I/O states

	switch(key_state_buffer1)
	{
		case key_state_0:
			if(key == 0)//按键被按下，状态转换到按键消抖和确认状态
			  key_state_buffer1 = key_state_1;
			break;
		case key_state_1:
	        if(key == 0)
	          {
				key_timer_cnt1 = 0;
				key_state_buffer1 = key_state_2;
				//按键仍然处于按下状态
				//消抖完成，key_timer开始准备计时
				//状态切换到按下时间计时状态
	           }
		else{key_state_buffer1 = key_state_0;}//按键已经抬起，回到按键初始状态
			break;  //完成软件消抖
		case key_state_2:
		    key_timer_cnt1++;
		    printf("\n---%d----\n",key_timer_cnt1);
		        if(key == 1)
			{
				key_return = key_click;  //按键抬起，产生一次click操作
				key_state_buffer1 = key_state_0;  //转换到按键初始状态
			}
			else if(key_timer_cnt1 >= 95)  //长按10s
			{
			        if(flag_work_mode||flag_connect_fail){
			         key_return = key_long_long;  //送回长按事件
				 key_state_buffer1 = key_state_3;  //转换到等待按键释放状态
				}
			}else if(key_timer_cnt1>=45 )//长按5s
			{
                            if((flag_airkiss_mode==1&&flag_connect_fail==0)||(flag_ap_mode==1&&flag_connect_fail==0)){
			        key_return = key_long;  //送回长按事件
				key_state_buffer1 = key_state_3;  //转换到等待按键释放状态
				}
			}
		break;
		case key_state_3:  //等待按键释放
		       if(key == 1)  //按键释放
			{
				key_state_buffer1 = key_state_0;  //切回按键初始状态
			}
			break;
	}
	return key_return;
}
void key_thread(void){
         unsigned char key;
         for(;;){
             vTaskDelay(100);
             key=key_driver();
             switch(key){
                   case 1 ://短按继电器控制
                        if(flag_produce_mode){
			                 printf("\n\n\n-----------produce_mode hand key -------\n\n\n");
                                  time_bl=120;//设置产测指示灯闪烁时间快慢
                             }else{
                                  if(OPT_READ){//当前是开状态
                                      printf("\n\n----prop_send_by_name Switch_Control  0-------\n\n");
            				          GPIO_WriteBit(OPT_PIN, 0);
            				          if(flag_work_mode){
            				          switch_control =0;
    				                  prop_send_by_name("Switch_Control");
				                  }
				              }else{
				                  printf("\n\n----prop_send_by_name Switch_Control  1-------\n\n");
        				          GPIO_WriteBit(OPT_PIN, 1);
        				          if(flag_work_mode){
        				          switch_control =1;
				                  prop_send_by_name("Switch_Control");
				                 }
				              }
    				   }
    		                    break;
		           case 3://长按按键进入模式切换5s
		                    if(flag_airkiss_mode==1&&flag_work_mode==0&&flag_ap_mode==0){
    				             //设置为AP方式
    				                printf("------set from airkiss  to AP mode---\n");
                                                char *argv[] = { "wifi", "aks_cls" };
                                                char *argv2[] = { "conf", "save" };
                                                char *argv3[] = { "reset" };
                                                adw_wifi_profile_sta_erase();
                                                vTaskDelay(200);
                                                adw_wifi_cli(2, argv);
                                                vTaskDelay(200);
                                                conf_cli(2, argv2);
                                                vTaskDelay(200);
                                                demo_reset_cmd(1, argv3);
			                }else if(flag_airkiss_mode==0&&flag_work_mode==0&&flag_ap_mode==1) {
        		                          //设置为airkiss模式
        		                        printf("------set from AP to airkiss mode---\n");
                                                char *argv[] = { "wifi", "aks_save" };
                                                char *argv2[] = { "conf", "save" };
                                                char *argv3[] = { "reset" };
                                                adw_wifi_profile_sta_erase();
                                                vTaskDelay(200);
                                                adw_wifi_cli(2, argv);
                                                vTaskDelay(200);
                                                conf_cli(2, argv2);
                                                vTaskDelay(200);
                                                demo_reset_cmd(1, argv3);
        				   }
		                   break;
                   case 4://长按10s进入恢复出厂设置状态（清除所有配置，包括WiFi配置，定时配置等）
                                     if(flag_work_mode==1||flag_connect_fail==1) {
                                                printf("------set from work to default airkiss mode and reset factory---\n");
                                                //①恢复出厂设置，继电器状态维持不变，进入airkiss默认配网
                                                conf_reset_factory();
                                                vTaskDelay(500);
                                                char *argv[] = { "wifi", "aks_save" };
                                                char *argv2[] = { "conf", "save" };
                                                char *argv3[] = { "reset" };
                                                adw_wifi_profile_sta_erase();
                                                vTaskDelay(200);
                                                adw_wifi_cli(2, argv);
                                                vTaskDelay(200);
                                                conf_cli(2, argv2);
                                                vTaskDelay(200);
                                                demo_reset_cmd(1, argv3);
                                       }
                    break;
		    default: break;
		}
	}
	vTaskDelete(NULL);
}
//建立按键线程任务
void KEY_Indicate(void)
{
  if(xTaskCreate(key_thread, ((const char*)"key_set"), STACKSIZE_KEY, NULL, tskIDLE_PRIORITY + 1, NULL) != pdPASS)
		printf("\n\r%s xTaskCreate(key_set) failed", __FUNCTION__);
}
void region_thread(void)
{
	vTaskDelay(2000);
    char *argv0[] = { "conf", "show" };
    conf_cli(2, argv0);
    vTaskDelay(1000);
   for(;;)
   {
     vTaskDelay(150);
     if(flag_region_get==1){
       powerOnRegion();
       flag_region_get=0;
     }
   }
    vTaskDelete(NULL);
}
void REGION_Indicate(void)
{
  if(xTaskCreate(region_thread, ((const char*)"region_thread"), 1024, NULL, tskIDLE_PRIORITY + 1, NULL) != pdPASS)
		printf("\n\r%s xTaskCreate(region_thread) failed", __FUNCTION__);
}

void prop_send_by_name(const char *name)
{
	enum ada_err err;

	err = ada_sprop_send_by_name(name);
	if (err) {
		log_put(LOG_INFO "demo: %s: send of %s: err %d",
		    __func__, name, err);
	}
}

/*
 * Demo set function for bool properties.
 */
static enum ada_err demo_led_set(struct ada_sprop *sprop,
				const void *buf, size_t len)
{
	int ret = 0;
         ret = ada_sprop_set_bool(sprop, buf, len);
	if (ret) {
		return ret;
	}
	if (sprop->val == &switch_control) {
	     printf("\n\n-----switch_control_* is %d------\n\n",switch_control);
	     GPIO_WriteBit(OPT_PIN,  switch_control);
	} else if (sprop->val == &green_led) {
		 set_led(led_green, green_led);
		 GPIO_WriteBit(OPT_PIN, green_led);
	}
	log_put(LOG_INFO "%s: %s set to %u",
	    __func__, sprop->name, *(u8 *)sprop->val);
	return AE_OK;
}

/*
 * Demo set function for integer and decimal properties.
 */
static enum ada_err demo_int_set(struct ada_sprop *sprop,
				const void *buf, size_t len)
{
	int ret;
    ret = ada_sprop_set_int(sprop, buf, len);
	if (ret) {
		return ret;
	}

	if (sprop->val == &input) {
		log_put(LOG_INFO "%s: %s set to %d",
		    __func__, sprop->name, input);
		output = input;
		prop_send_by_name("output");
	} else if (sprop->val == &decimal_in) {
		log_put(LOG_INFO "%s: %s set to %d",
		    __func__, sprop->name, decimal_in);
		decimal_out = decimal_in;
		prop_send_by_name("decimal_out");
	} else {
		return AE_NOT_FOUND;
	}
	return AE_OK;
}

/*
 * Demo set function for string properties.
 */
static enum ada_err demo_cmd_set(struct ada_sprop *sprop,
				const void *buf, size_t len)
{
	int ret;
    ret = ada_sprop_set_string(sprop, buf, len);
	if (ret) {
		return ret;
	}

	prop_send_by_name("log");
	log_put(LOG_INFO "%s: cloud set %s to \"%s\"",
	    __func__, sprop->name, cmd_buf);
	return AE_OK;
}



