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
#include "config_allinfo.h"


// oem                   20
// oemmodel          20
// oemkey              50
// region                10
// dsn                     20
// publickey            400
// total                    520
unsigned int  SA_ADDRESS=0x1d0000;
unsigned int  US_ADDRESS=0x1e0000;
unsigned int  EU_ADDRESS=0x1f0000;
unsigned int  DEFAULT_ADDRESS=0x1d0000;
//GET DATA BUF
char GET_CONFIG_BUF[600];

int SET_ADDRESS_FLASH(char *region,unsigned int address)
{
   char *psa="sa";
   char *pus="us";
   char *peu="eu";
   if(*region==*psa)
   {
      SA_ADDRESS=address;
   }else if(*region==*pus){
      US_ADDRESS=address;
   }else if(*region==*peu){
      EU_ADDRESS=address;
   }else{
     return 2;
   }
  return 0;
}

enum set_error OEM_SET(const uint8_t *oem,char * region,int oem_len)
{
   flash_t  flash;
   char *psa="sa";
   char *pus="us";
   char *peu="eu";
   if(oem_len>20)
   {
     return 1;
   }
   if(*region==*psa)
   {
      flash_stream_write(&flash,  SA_ADDRESS, 20, oem);
   }else if(*region==*pus){
      flash_stream_write(&flash,  US_ADDRESS, 20, oem);
   }else if(*region==*peu){
      flash_stream_write(&flash,  EU_ADDRESS, 20, oem);
   }else{
     return 2;
   }
  return 0;
}
enum  get_error OEM_GET(char *region,char *GetBuf)
{
   flash_t  flash;
   char *psa="sa";
   char *pus="us";
   char *peu="eu";
  if(*region==*psa)
   {
     flash_stream_read(&flash,   SA_ADDRESS, 20, GetBuf);
     // printcli("\n--sa oem- :%s--\n",GetBuf);
   }else if(*region==*pus){
     flash_stream_read(&flash,   US_ADDRESS, 20, GetBuf);
      //printcli("\n--us oem :%s--\n",GetBuf);
   }else if(*region==*peu){
     flash_stream_read(&flash,   EU_ADDRESS, 20, GetBuf);
     // printcli("\n--eu oem :%s--\n",GetBuf);
   }else{
     return 2;
   }
  return 0;
}
enum  set_error OEMMODEL_SET(const uint8_t * oemmodel,char *region,int oemmodel_len)
{
   flash_t  flash;
   char *psa="sa";
   char *pus="us";
   char *peu="eu";
   if(oemmodel_len>20)
   {
     return 1;
   }
   if(*region==*psa)
   {
      flash_stream_write(&flash,  SA_ADDRESS+20, 20, oemmodel);
   }else if(*region==*pus){
      flash_stream_write(&flash,  US_ADDRESS+20, 20, oemmodel);
   }else if(*region==*peu){
      flash_stream_write(&flash,  EU_ADDRESS+20, 20, oemmodel);
   }else{
     return 2;
   }
  return 0;
}
enum  get_error OEMMODEL_GET(char *region,char *GetBuf)
{
   flash_t  flash;
   char *psa="sa";
   char *pus="us";
   char *peu="eu";
   if(*region==*psa)
   {
     flash_stream_read(&flash,   SA_ADDRESS+20, 20, GetBuf+20);
     //printcli("\n--sa oem model-:%s--\n",GetBuf+20);
   }else if(*region==*pus){
     flash_stream_read(&flash,   US_ADDRESS+20, 20, GetBuf+20);
    // printcli("\n--us oem model:%s--\n",GetBuf+20);
   }else if(*region==*peu){
     flash_stream_read(&flash,   EU_ADDRESS+20, 20, GetBuf+20);
   // printcli("\n--eu oem model:%s--\n",GetBuf+20);
   }else{
     return 2;
   }
  return 0;
}
enum set_error OEMKEY_SET(const uint8_t  * oemkey,char * region,int oemkey_len)
{
   flash_t	flash;
   char *psa="sa";
   char *pus="us";
   char *peu="eu";
   if(oemkey_len>50)
   {
     return 1;
   }
   if(*region==*psa)
   {
      flash_stream_write(&flash,  SA_ADDRESS+40, 50, oemkey);
   }else if(*region==*pus){
      flash_stream_write(&flash,  US_ADDRESS+40, 50, oemkey);
   }else if(*region==*peu){
      flash_stream_write(&flash,  EU_ADDRESS+40, 50, oemkey);
   }else{
     return 2;
   }
  return 0;
}

enum get_error OEMKEY_GET(char *region,char *GetBuf)
{
   flash_t  flash;
   char *psa="sa";
   char *pus="us";
   char *peu="eu";
   if(*region==*psa)
   {
     flash_stream_read(&flash,   SA_ADDRESS+40, 50, GetBuf+40);
     //printcli("\n--sa oem key-:%s--\n",GetBuf+40);
   }else if(*region==*pus){
     flash_stream_read(&flash,   US_ADDRESS+40, 50, GetBuf+40);
     //printcli("\n--us oem key:%s--\n",GetBuf+40);
   }else if(*region==*peu){
     flash_stream_read(&flash,   EU_ADDRESS+40, 50, GetBuf+40);
     //printcli("\n--eu oem key:%s--\n",GetBuf+40);
   }else{
     return 2;
   }
  return 0;
}


enum set_error REGION_SET(const uint8_t *region,int region_len)
{
   flash_t	flash;
   char *psa="sa";
   char *pus="us";
   char *peu="eu";
   if(region_len>10)
   {
     return 1;
   }
   if(*region==*psa)
   {
      flash_stream_write(&flash,  SA_ADDRESS+90, 10, psa);
   }else if(*region==*pus){
      flash_stream_write(&flash,  US_ADDRESS+90, 10, pus);
   }else if(*region==*peu){
      flash_stream_write(&flash,  EU_ADDRESS+90, 10, pus);
   }else{
     return 2;
   }
  return 0;
}
enum get_error REGION_GET(char *region,char *GetBuf)
{
   flash_t  flash;
   char *psa="sa";
   char *pus="us";
   char *peu="eu";
   if(*region==*psa)
   {
     flash_stream_read(&flash,   SA_ADDRESS+90, 10, GetBuf+90);
     //printcli("\n--sa  region:%s--\n",GetBuf+90);
   }else if(*region==*pus){
     flash_stream_read(&flash,   US_ADDRESS+90, 10, GetBuf+90);
     //printcli("\n--us region:%s--\n",GetBuf+90);
   }else if(*region==*peu){
     flash_stream_read(&flash,   EU_ADDRESS+90, 10, GetBuf+90);
     //printcli("\n--eu region:%s--\n",GetBuf+90);
   }else{
     return 2;
   }
  return 0;
}
enum set_error  DSN_SET(const uint8_t * dsn,char *region,int dsn_len)
{
   flash_t	flash;
   char *psa="sa";
   char *pus="us";
   char *peu="eu";
   if(dsn_len>20)
   {
     return 1;
   }
   if(*region==*psa)
   {
      flash_stream_write(&flash,  SA_ADDRESS+100, 20, dsn);
   }else if(*region==*pus){
      flash_stream_write(&flash,  US_ADDRESS+100, 20, dsn);
   }else if(*region==*peu){
      flash_stream_write(&flash,  EU_ADDRESS+100, 20, dsn);
   }else{
     return 2;
   }
  return 0;
}
enum get_error DSN_GET(char *region,char *GetBuf)
{
   flash_t  flash;
   char *psa="sa";
   char *pus="us";
   char *peu="eu";
   if(*region==*psa)
   {
     flash_stream_read(&flash,   SA_ADDRESS+100, 20, GetBuf+100);
     //printcli("\n--sa dsn:%s--\n",GetBuf+100);
   }else if(*region==*pus){
     flash_stream_read(&flash,   US_ADDRESS+100, 20, GetBuf+100);
     //printcli("\n--us dsn:%s--\n",GetBuf+100);
   }else if(*region==*peu){
     flash_stream_read(&flash,   EU_ADDRESS+100, 20, GetBuf+100);
     //printcli("\n--eu dsn:%s--\n",GetBuf+100);
   }else{
     return 2;
   }
  return 0;
}
enum set_error  PUBKEY_SET(const uint8_t *pubkey,char *region,int pubkey_len)
{
   flash_t	flash;
   char *psa="sa";
   char *pus="us";
   char *peu="eu";
   if(pubkey_len>400)
   {
     return 1;
   }
   if(*region==*psa)
   {
      if(flash_stream_write(&flash,  SA_ADDRESS+120, 400, pubkey)){
         return 0;
      }
   }else if(*region==*pus){
      if(flash_stream_write(&flash,  US_ADDRESS+120, 400, pubkey)){
         return 0;
      }
   }else if(*region==*peu){
      if(flash_stream_write(&flash,  EU_ADDRESS+120, 400, pubkey)){
         return 0;
      }
   }else{
     return 2;
   }
  //return 0;
}

enum get_error PUBKEY_GET(char *region,char *GetBuf)
{
    flash_t  flash;
    char *psa="sa";
   char *pus="us";
   char *peu="eu";
   if(*region==*psa)
   {
     flash_stream_read(&flash,   SA_ADDRESS+120, 400, GetBuf+120);
     //printcli("\n--sa pubkey:%s--\n",GetBuf+120);
   }else if(*region==*pus){
     flash_stream_read(&flash,   US_ADDRESS+120, 400, GetBuf+120);
     //printcli("\n--us pubkey:%s--\n",GetBuf+120);
   }else if(*region==*peu){
     flash_stream_read(&flash,   EU_ADDRESS+120, 400, GetBuf+120);
    //printcli("\n--eu pubkey:%s--\n",GetBuf+120);
   }else{
     return 2;
   }
  return 0;
}
void  CONFIG_SA_INFO(void)
{
     printf("\n---sa set----\n");
     OEM_SET(OEM_ID_SA,REGION_SA,20);
     OEMMODEL_SET(OEM_MODEL_SA,REGION_SA,20);
     OEMKEY_SET(OEM_KEY_SA,REGION_SA,50);
     REGION_SET(REGION_SA,10);
     PUBKEY_SET(PUBLIC_KEY_SA,REGION_SA,400);
     DSN_SET(OEM_DSN_SA,REGION_SA,20);
}
void  CONFIG_US_INFO(void)
{
     printf("\n---us set----\n");
     OEM_SET(OEM_ID_US,REGION_US,20);
     OEMMODEL_SET(OEM_MODEL_US,REGION_US,20);
     OEMKEY_SET(OEM_KEY_US,REGION_US,50);
     REGION_SET(REGION_US,10);
     PUBKEY_SET(PUBLIC_KEY_US,REGION_US,400);
     DSN_SET(OEM_DSN_US,REGION_US,20);
}
void  CONFIG_EU_INFO(void)
{
     printf("\n---eu set----\n");
     OEM_SET(OEM_ID_EU,REGION_EU,20);
     OEMMODEL_SET(OEM_MODEL_EU,REGION_EU,20);
     OEMKEY_SET(OEM_KEY_EU,REGION_EU,50);
     REGION_SET(REGION_EU,10);
     PUBKEY_SET(PUBLIC_KEY_EU,REGION_EU,400);
     DSN_SET(OEM_DSN_EU,REGION_EU,20);
}
 void CONFIG_ALL_INFO(void){
              printf("\n---sa set----\n");
              OEM_SET(OEM_ID_SA,REGION_SA,20);
              OEMMODEL_SET(OEM_MODEL_SA,REGION_SA,20);
              OEMKEY_SET(OEM_KEY_SA,REGION_SA,50);
              REGION_SET(REGION_SA,10);
              PUBKEY_SET(PUBLIC_KEY_SA,REGION_SA,400);
              DSN_SET(OEM_DSN_SA,REGION_SA,20);

              printf("\n---us set----\n");
              OEM_SET(OEM_ID_US,REGION_US,20);
              OEMMODEL_SET(OEM_MODEL_US,REGION_US,20);
              OEMKEY_SET(OEM_KEY_US,REGION_US,50);
              REGION_SET(REGION_US,10);
              PUBKEY_SET(PUBLIC_KEY_US,REGION_US,400);
              DSN_SET(OEM_DSN_US,REGION_US,20);


              printf("\n---eu set----\n");
              OEM_SET(OEM_ID_EU,REGION_EU,20);
              OEMMODEL_SET(OEM_MODEL_EU,REGION_EU,20);
              OEMKEY_SET(OEM_KEY_EU,REGION_EU,50);
              REGION_SET(REGION_EU,10);
              PUBKEY_SET(PUBLIC_KEY_EU,REGION_EU,400);
              DSN_SET(OEM_DSN_EU,REGION_EU,20);
}

 static int conf_oem_set_string(char *dest, char *src)
{
	int len;

	/*
	 * Work-around for parser in early SDK versions, drop in ada-1.2.
	 */
	if (!strcmp(src, "\"\"")) {
		src = "";
	}
	if (!hostname_valid(src)) {
		printcli("error: invalid value");
		return -1;
	}
	len = snprintf(dest, CONF_OEM_MAX + 1, "%s", src);
	if (len > CONF_OEM_MAX) {
		printcli("error: value too long");
		return -1;
	}
	return 0;
}


enum conf_error oem_set_key_3in1(char *key, size_t key_len)
{
     	char buf[CONF_OEM_KEY_MAX + 1];
	char pub_key[CLIENT_CONF_PUB_KEY_LEN];
	int pub_key_len;
	int rc;
	size_t len = key_len;
        if (len == '\0') {
		oem_key_len = 0;
		goto out;
	}
        if (len > sizeof(buf) - 1) {
		return CONF_ERR_RANGE;
	}
	//add
	conf_oem_set_string(oem,(char *)GET_CONFIG_BUF);
	conf_oem_set_string(oem_model,(char *)(GET_CONFIG_BUF+20));
	//end add
	memcpy(buf, key, len);
	len += snprintf(buf + len, sizeof(buf) - 1 - len, " %s %s", (char *)GET_CONFIG_BUF, (char *)(GET_CONFIG_BUF+20));
	buf[len] = '\0';

	pub_key_len = adap_conf_pub_key_get(pub_key, sizeof(pub_key));
	if (pub_key_len <= 0) {
		conf_log(LOG_ERR "pub key not set");
		return CONF_ERR_RANGE;
	}

	rc = client_auth_encrypt(pub_key, pub_key_len,
	    oem_key, CONF_OEM_KEY_MAX, buf);
	if (rc < 0) {
		conf_log(LOG_ERR "oem_key encryption failed.  rc %d", rc);
		return CONF_ERR_RANGE;
	}
	oem_key_len = rc;
out:
	rc = adap_conf_set(ADA_CONF_OEM_KEY, oem_key, oem_key_len);
	if (rc) {
	   conf_log(LOG_ERR "oem_key save failed");
	}
	return rc;
}

void SA_SELECT(void)
{
    print("\n\n---sa----\n\n");
    OEM_GET(REGION_SA,GET_CONFIG_BUF);
    OEMMODEL_GET(REGION_SA,GET_CONFIG_BUF);
    OEMKEY_GET(REGION_SA,GET_CONFIG_BUF);
    REGION_GET(REGION_SA,GET_CONFIG_BUF);
    PUBKEY_GET(REGION_SA,GET_CONFIG_BUF);
    DSN_GET(REGION_SA,GET_CONFIG_BUF);
    //加密key连接云
    char *argv[] = { "id", "dev_id",(char *)(GET_CONFIG_BUF+100) };
    ada_conf_id_cli(3,argv);
    client_set_region((char *)GET_CONFIG_BUF+90);
    oem_set_key_3in1((char *)(GET_CONFIG_BUF+40), strlen((char *)(GET_CONFIG_BUF+40)));
}


void US_SELECT(void)
{
   print("\n\n---us----\n\n");
   OEM_GET(REGION_US,GET_CONFIG_BUF);
   OEMMODEL_GET(REGION_US,GET_CONFIG_BUF);
   OEMKEY_GET(REGION_US,GET_CONFIG_BUF);
   REGION_GET(REGION_US,GET_CONFIG_BUF);
   PUBKEY_GET(REGION_US,GET_CONFIG_BUF);
   DSN_GET(REGION_US,GET_CONFIG_BUF);
   //加密key连接云
   char *argv[] = { "id", "dev_id",(char *)(GET_CONFIG_BUF+100) };
   ada_conf_id_cli(3,argv);
   client_set_region((char *)GET_CONFIG_BUF+90);
   oem_set_key_3in1((char *)(GET_CONFIG_BUF+40), strlen((char *)(GET_CONFIG_BUF+40)));
}

void EU_SELECT(void)
{
      print("\n\n---eu----\n\n");
      OEM_GET(REGION_EU,GET_CONFIG_BUF);
      OEMMODEL_GET(REGION_EU,GET_CONFIG_BUF);
      OEMKEY_GET(REGION_EU,GET_CONFIG_BUF);
      REGION_GET(REGION_EU,GET_CONFIG_BUF);
      PUBKEY_GET(REGION_EU,GET_CONFIG_BUF);
      DSN_GET(REGION_EU,GET_CONFIG_BUF);
       //加密key连接云
      char *argv[] = { "id", "dev_id",(char *)(GET_CONFIG_BUF+100) };
      ada_conf_id_cli(3,argv);
      client_set_region((char *)GET_CONFIG_BUF+90);
      oem_set_key_3in1((char *)(GET_CONFIG_BUF+40), strlen((char *)(GET_CONFIG_BUF+40)));
}

