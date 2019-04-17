#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ayla/utypes.h>
#include <ayla/assert.h>
#include <ayla/tlv.h>
#include <ayla/conf_token.h>
#include <ayla/conf.h>
#include <ayla/conf_flash.h>
#include <ayla/log.h>
#include <ayla/mod_log.h>
#include <ayla/endian.h>
#include <ayla/crc.h>
#include <ayla/clock.h>
#include <ayla/utf8.h>
#include <ayla/malloc.h>
#include "flash_api.h"
#include "device_lock.h"
#include <ada/err.h>
#include <ayla/parse.h>
#ifdef AYLA_BC
#include <ayla/gpio.h>
#endif
#include <ada/client.h>
#include <ada/ada_conf.h>
#include "conf.h"

/*
*  The following interfaces and names remain unchanged
*
*/
//REGION DEFINE
#define REGION_SA         "sa"
#define REGION_US         "us"
#define REGION_EU         "eu"
//OEM ID  DEFINE
#define OEM_ID_SA          "495c64f1"
#define OEM_ID_US          "1e24aafd"
#define OEM_ID_EU          "OEM_ID_EU"

//OEM MODEL  DEFINE
#define OEM_MODEL_SA     "SN0-01-0-001"
#define OEM_MODEL_US     "SN0-01-0-001"
#define OEM_MODEL_EU     "OEM_MODEL_EU"

//OEM KEY  DEFINE
#define OEM_KEY_SA     "2ecca535bdf23a2f55b797cc08e4dfce"
#define OEM_KEY_US     "36d2ab56d6ed4a06895dbe9979c0d731"
#define OEM_KEY_EU     "OEM_KEY_EU"

//DSN  DEFINE
#define OEM_DSN_SA     "SC000W000138234"
#define OEM_DSN_US     "AC000W006408965"
#define OEM_DSN_EU     "eu_dsn"
//SA public key  DEFINE
#define PUBLIC_KEY_SA      "MIIBCgKCAQEA/QDEMr+knCm9oGOp6Pe2VBShx/8gckKEFHQ5zVXurhMBXtgZFDZqIR5HHANpJHdmwKpQNxdRUFKyYQil006sFoY7pY2x3KKZdhCP/ocp9oWPRhNtWojSG8MmwKFkEeisuQpHauhyzM1teNPCtAexP7cnfhU83ZDM7cS/0sJ93aPfXAuF6ZSJfLGv/0iScf4uttpcR1Ro2FUghFE3UQhbRb8llrSnJBn0q/jsyQfP3HXMjS/zmlRrYdwVRLK2ipkPtrnOjrZeL71rqvhJzXLc2+DuXomWaSZC3R6Uh89M8B/d5uGcsmNOLVYqjnSdpqq+SJi7JDDoAUPfxT7pYRFKdQIDAQAB"

//US public key  DEFINE
#define PUBLIC_KEY_US      "MIIBCgKCAQEAhZa9fd3IksD7n9gQU1mEgqRFxHTaUKM2Gc4TsnnP/glY4a9FgP9QyK0vYL9afez+YfzF0c1jKcvgT6yTpX+cFkrtY4cV0WZ1gUw07a/yLH+n4hTPXz4hN6E8Ib/sE9KWkXvqjihg8gv0EEU9ehCJRg67AuDIj9vt5rQrlzFu4rKUw6OAQ4DEc0J+jSBJgwO5+V/qd07bZN335jzwIc80D7+toSIOvD9swf1K3pFMFXdSV/+nhaH0oD01aeuzXz8wzdaMeNK34sEH429j3S1ouJbUlKNqP7i1rNqH+P8ut7Zzt5P9/ukqNEFmPixKBs4MMUqt80rQa4FSuH2ffbRFEQIDAQAB"

//EU public key  DEFINE
#define PUBLIC_KEY_EU      "MIIBCgKCAQEAuiOSJjYpNmBeEtWAJLHS7lelVRnCLbVIbAkgDo9xCyHMo0YrXNIx07p9em8mK2sghha5k2pzKKNMb8A6pzmOGc6LbYT6EKD2feIRBwdVUNYguf+ZcP3F6LAqBDdUMipcFBGzZTEu1gEmACdcepgRlRtZ0FeY4f8GDZ/2eXkeF4Po4du08kLEsvoWiNavxllenShHfByE5vQhzDeowUNHnt5Fwk7BygYaLHzwhHDSQK76MWc3UaiB85Urg8SnWnCa7TTQvsbJtgca7d3ghDL0q0mpwzn5jzNzfB4Crl4RiUTmCdkzwxE5l5Ym09Chshy9ylxpOmTbchPRJNjwrQVNKwIDAQAB"

enum set_error{
      set_error_none,
      set_len_error,
      set_region_error,
};
enum get_error{
      get_error_none,
      get_len_error,
      get_region_error,
};


//SETTING
enum set_error OEM_SET(const uint8_t *oem,char * region,int oem_len);
enum set_error OEMMODEL_SET(const uint8_t * oemmodel,char *region,int oemmodel_len);
enum set_error OEMKEY_SET(const uint8_t  * oemkey,char * region,int oemkey_len);
enum set_error REGION_SET(const uint8_t *region,int region_len);
enum set_error DSN_SET(const uint8_t * dsn,char *region,int dsn_len);
enum set_error PUBKEY_SET(const uint8_t *pubkey,char *region,int pubkey_len);


//GETTING
enum  get_error OEM_GET(char *region,char *GetBuf);
enum  get_error OEMMODEL_GET(char *region,char *GetBuf);
enum get_error  OEMKEY_GET(char *region,char *GetBuf);
enum get_error  REGION_GET(char *region,char *GetBuf);
enum get_error  DSN_GET(char *region,char *GetBuf);
enum get_error  PUBKEY_GET(char *region,char *GetBuf);

int SET_ADDRESS_FLASH(char *region,unsigned int address);

//用户一键写入3个域的所有信息
//使用情形:根据头文件中定义格式
void  CONFIG_ALL_INFO (void);
void  CONFIG_SA_INFO(void);
void  CONFIG_US_INFO(void);
void  CONFIG_EU_INFO(void);

void SA_SELECT(void);
void US_SELECT(void);
void EU_SELECT(void);












