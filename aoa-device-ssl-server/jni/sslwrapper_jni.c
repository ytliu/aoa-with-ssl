


#define LOGTAG "sslw"

#include <dlfcn.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/resource.h>

#include <jni.h>

#include "hu_uti.h"
#include "hu_aad.h"

const char * copyright = "Copyright (c) 2011-2015 Michael A. Reid. All rights reserved.";

int ssl_init_done = 0;
void *ssl_fd = NULL;
char lib_name[DEF_BUF] = "/data/app/cn.sjtu.ipads-1/lib/arm/libsslwrapper_jnio.so";

jint (* Java_com_google_android_gms_car_senderprotocol_SslWrapper_nativeInit_o                      ) (JNIEnv * env, jobject thiz, jstring pemPublicKeyCert1, jstring pemPublicKeyCert2, jbyteArray binPrivateKey);

jint (* Java_com_google_android_gms_car_senderprotocol_SslWrapper_nativeHandshakeDataEnqueue_o      ) (JNIEnv * env, jobject thiz, jobject bBuf, jint idx, jint len);
jint (* Java_com_google_android_gms_car_senderprotocol_SslWrapper_nativeHandshake_o                 ) (JNIEnv * env, jobject thiz)                                  ;
void (* Java_com_google_android_gms_car_senderprotocol_SslWrapper_nativeHandshakeDataDequeue_o      ) (JNIEnv * env, jobject thiz, jobject bBuf, jint len)          ; // Get handshake response

jint (* Java_com_google_android_gms_car_senderprotocol_SslWrapper_nativeDecryptionPipelineEnqueue_o ) (JNIEnv * env, jobject thiz, jobject bBuf, jint len)          ; // Return len
jint (* Java_com_google_android_gms_car_senderprotocol_SslWrapper_nativeDecryptionPipelinePending_o ) (JNIEnv * env, jobject thiz)                                  ; // Return len
jint (* Java_com_google_android_gms_car_senderprotocol_SslWrapper_nativeDecryptionPipelineDequeue_o ) (JNIEnv * env, jobject thiz, jobject bBuf, jint len)          ; // Return len

jint (* Java_com_google_android_gms_car_senderprotocol_SslWrapper_nativeEncryptionPipelineEnqueue_o ) (JNIEnv * env, jobject thiz, jobject bBuf, jint idx, jint len); // Return len
jint (* Java_com_google_android_gms_car_senderprotocol_SslWrapper_nativeEncryptionPipelineDequeue_o ) (JNIEnv * env, jobject thiz, jobject bBuf, jint len)          ; // Return len

int neuter = 0;     // 0 = Shim mode to monitor AA<>HU      1 = Neuter encryption for HUE testing

int ssl_init () {

  if (ssl_init_done)
    return (0);

  ssl_init_done = 1;

  if (file_get ("/sdcard/aaneuter")) {
    neuter = 1;
    logd ("neuter encryption mode");
    return (0);
  }
  else {
    neuter = 0;
    logd ("pass-through shim mode");
  }

  if (! file_get (lib_name))
    lib_name = lib_name2;

  ssl_fd = dlopen (lib_name, RTLD_LAZY);                              // Load library
  if (ssl_fd == NULL) {
    loge ("Could not load library '%s'", lib_name);
    return (-1);
  }
  logd ("Loaded %s  ssl_fd: %d", lib_name, ssl_fd);

  Java_com_google_android_gms_car_senderprotocol_SslWrapper_nativeInit_o                      = dlsym (ssl_fd, "Java_com_google_android_gms_car_senderprotocol_SslWrapper_nativeInit");
  Java_com_google_android_gms_car_senderprotocol_SslWrapper_nativeHandshakeDataEnqueue_o      = dlsym (ssl_fd, "Java_com_google_android_gms_car_senderprotocol_SslWrapper_nativeHandshakeDataEnqueue");
  Java_com_google_android_gms_car_senderprotocol_SslWrapper_nativeHandshake_o                 = dlsym (ssl_fd, "Java_com_google_android_gms_car_senderprotocol_SslWrapper_nativeHandshake");
  Java_com_google_android_gms_car_senderprotocol_SslWrapper_nativeHandshakeDataDequeue_o      = dlsym (ssl_fd, "Java_com_google_android_gms_car_senderprotocol_SslWrapper_nativeHandshakeDataDequeue");
  Java_com_google_android_gms_car_senderprotocol_SslWrapper_nativeDecryptionPipelineEnqueue_o = dlsym (ssl_fd, "Java_com_google_android_gms_car_senderprotocol_SslWrapper_nativeDecryptionPipelineEnqueue");
  Java_com_google_android_gms_car_senderprotocol_SslWrapper_nativeDecryptionPipelinePending_o = dlsym (ssl_fd, "Java_com_google_android_gms_car_senderprotocol_SslWrapper_nativeDecryptionPipelinePending");
  Java_com_google_android_gms_car_senderprotocol_SslWrapper_nativeDecryptionPipelineDequeue_o = dlsym (ssl_fd, "Java_com_google_android_gms_car_senderprotocol_SslWrapper_nativeDecryptionPipelineDequeue");
  Java_com_google_android_gms_car_senderprotocol_SslWrapper_nativeEncryptionPipelineEnqueue_o = dlsym (ssl_fd, "Java_com_google_android_gms_car_senderprotocol_SslWrapper_nativeEncryptionPipelineEnqueue");
  Java_com_google_android_gms_car_senderprotocol_SslWrapper_nativeEncryptionPipelineDequeue_o = dlsym (ssl_fd, "Java_com_google_android_gms_car_senderprotocol_SslWrapper_nativeEncryptionPipelineDequeue");


  if (! Java_com_google_android_gms_car_senderprotocol_SslWrapper_nativeInit_o                     ) loge ("No Java_com_google_android_gms_car_senderprotocol_SslWrapper_nativeInit");
  if (! Java_com_google_android_gms_car_senderprotocol_SslWrapper_nativeHandshakeDataEnqueue_o     ) loge ("No Java_com_google_android_gms_car_senderprotocol_SslWrapper_nativeHandshakeDataEnqueue");
  if (! Java_com_google_android_gms_car_senderprotocol_SslWrapper_nativeHandshake_o                ) loge ("No Java_com_google_android_gms_car_senderprotocol_SslWrapper_nativeHandshake");
  if (! Java_com_google_android_gms_car_senderprotocol_SslWrapper_nativeHandshakeDataDequeue_o     ) loge ("No Java_com_google_android_gms_car_senderprotocol_SslWrapper_nativeHandshakeDataDequeue");
  if (! Java_com_google_android_gms_car_senderprotocol_SslWrapper_nativeDecryptionPipelineEnqueue_o) loge ("No Java_com_google_android_gms_car_senderprotocol_SslWrapper_nativeDecryptionPipelineEnqueue");
  if (! Java_com_google_android_gms_car_senderprotocol_SslWrapper_nativeDecryptionPipelinePending_o) loge ("No Java_com_google_android_gms_car_senderprotocol_SslWrapper_nativeDecryptionPipelinePending");
  if (! Java_com_google_android_gms_car_senderprotocol_SslWrapper_nativeDecryptionPipelineDequeue_o) loge ("No Java_com_google_android_gms_car_senderprotocol_SslWrapper_nativeDecryptionPipelineDequeue");
  if (! Java_com_google_android_gms_car_senderprotocol_SslWrapper_nativeEncryptionPipelineEnqueue_o) loge ("No Java_com_google_android_gms_car_senderprotocol_SslWrapper_nativeEncryptionPipelineEnqueue");
  if (! Java_com_google_android_gms_car_senderprotocol_SslWrapper_nativeEncryptionPipelineDequeue_o) loge ("No Java_com_google_android_gms_car_senderprotocol_SslWrapper_nativeEncryptionPipelineDequeue");
}



int en_dump_init = 1;
int en_dump_hs   = 1;
int en_dump_data = 1;

unsigned char bytear_buf [65536] = {0};
int max_dump_ba = 65536;

int logd_jstring (JNIEnv * env, char * prefix, jstring java_string) {
  const char * c_string = (*env)->GetStringUTFChars (env, java_string, 0);
  logd ("%s %s  ", prefix, c_string);
  (*env)->ReleaseStringUTFChars (env, java_string, c_string);
  return (0);
}

int logd_jbytear (JNIEnv * env, char * prefix, jbyteArray java_bytear) {
  jint len = (*env)->GetArrayLength (env, java_bytear);
  (*env)->GetByteArrayRegion (env, java_bytear, 0, len, (jbyte *) bytear_buf);
  logd ("%s len: %d", prefix, len);
  if (len > max_dump_ba)
    len = max_dump_ba;
  hex_dump (prefix, 16, (unsigned char *) & bytear_buf, len);
  return (0);
}


int jbytebu_num_dumps = 0;
int jbytebu_max_dumps = 64;//256;//1024;
int max_dump_jbytebu_hs = 16384;//4096;//64;  // max bytes to dump

int logd_jbytebu (JNIEnv * env, char * prefix, jobject java_bytebu, jint idx, jint len, int type) {
  if (jbytebu_num_dumps ++ >= jbytebu_max_dumps) {
    if (! file_get ("/sdcard/aanomax"))
      return (0);
  }
  unsigned char * buf = (unsigned char *) (*env)->GetDirectBufferAddress (env, java_bytebu);// ByteBuffer must be created using an allocateDirect() factory method

  if (jbytebu_num_dumps > 64 && ! file_get ("/sdcard/aaall")) {
    if (type == 2 && buf [0] == 0x00 && (buf [1] == 0 || buf [1] == 1)) // Tx Video
      return (0);
    if (type == 1 && buf [0] == 0x80 && buf [1] == 0x04)                // Rx Video Ack
      return (0);
    if (type == 1 && buf [0] == 0x00 && buf [1] == 0x0b)                // Rx Ping request
      return (0);
    if (type == 2 && buf [0] == 0x00 && buf [1] == 0x0c)                // Tx Ping response
      return (0);
  }

  if (ena_log_verbo || len > 48)
    logd ("%s buf: %p  idx: %d  len: %d", prefix, buf, idx, len);
  if (buf == NULL || len <= 0)
    return (0);

  if (type == 1 || type == 2)                                         // If Rx or Tx...
    hu_aad_dmp (prefix, type, & buf [idx], len);
  else {
    int dumplen = len;
    if (len > max_dump_jbytebu_hs)
      dumplen = max_dump_jbytebu_hs;
    hex_dump (prefix, 16, & buf [idx], dumplen);
  }

  return (0);
}

jint Java_com_google_android_gms_car_senderprotocol_SslWrapper_nativeInit (JNIEnv * env, jobject thiz, jstring pemPublicKeyCert1, jstring pemPublicKeyCert2, jbyteArray binPrivateKey) {
  ssl_init ();

  if (en_dump_init) {
    logd_jstring (env, "Init pemPublicKeyCert1: ", pemPublicKeyCert1);
    logd_jstring (env, "Init pemPublicKeyCert2: ", pemPublicKeyCert2);
    logd_jbytear (env, "Init binPrivateKey:     ", binPrivateKey);
  }

  jint ret = -1;
  if (neuter) {
    ret = JNI_TRUE;
    logd ("INIT !!!!!!!!!!!!!!!!!!!!!!!!    Init ret: %d", ret);
    return (ret);                                                // Return true on success
  }

  if (Java_com_google_android_gms_car_senderprotocol_SslWrapper_nativeInit_o)
    ret = Java_com_google_android_gms_car_senderprotocol_SslWrapper_nativeInit_o (env, thiz, pemPublicKeyCert1, pemPublicKeyCert2, binPrivateKey);
  else
    loge ("NO %s", __func__);
  logd ("Init ret: %d", ret);
  return (ret);
}

void Java_com_google_android_gms_car_senderprotocol_SslWrapper_nativeHandshakeDataEnqueue (JNIEnv * env, jobject thiz, jobject bBuf, jint idx, jint len) { // Pass handshake request

  if (en_dump_hs)
    logd_jbytebu (env, "HE: ", bBuf, idx, len, 0);
  else
    logd ("HE bBuf: %p  idx: %d  len: %d", bBuf, idx, len);

  if (neuter) 
    return;

  if (Java_com_google_android_gms_car_senderprotocol_SslWrapper_nativeHandshakeDataEnqueue_o)
    Java_com_google_android_gms_car_senderprotocol_SslWrapper_nativeHandshakeDataEnqueue_o (env, thiz, bBuf, idx, len);
  else
    loge ("NO %s", __func__);
}

jint Java_com_google_android_gms_car_senderprotocol_SslWrapper_nativeHandshake (JNIEnv * env, jobject thiz) {                                    // Return len of handshake response
  jint retlen = -1;
  if (neuter) {
    retlen = 8;
    logd ("HS retlen: %d", retlen);
    return (retlen);
  }

  if (Java_com_google_android_gms_car_senderprotocol_SslWrapper_nativeHandshake_o)
    retlen = Java_com_google_android_gms_car_senderprotocol_SslWrapper_nativeHandshake_o (env, thiz);
  else
    loge ("NO %s", __func__);

  logd ("HS retlen: %d", retlen);
  return (retlen);
}
void Java_com_google_android_gms_car_senderprotocol_SslWrapper_nativeHandshakeDataDequeue (JNIEnv * env, jobject thiz, jobject bBuf, jint len) {           // Get handshake response

  if (neuter) {
    logd ("HD passed len: %d", len);
    return;
  }

  if (Java_com_google_android_gms_car_senderprotocol_SslWrapper_nativeHandshakeDataDequeue_o)
    Java_com_google_android_gms_car_senderprotocol_SslWrapper_nativeHandshakeDataDequeue_o (env, thiz, bBuf, len);
  else
    loge ("NO %s", __func__);

  if (en_dump_hs)
    logd_jbytebu (env, "HD: ", bBuf, 0, len, 0);
  else
    logd ("HD passed len: %d", len);
}

#define MAX_BUF 65536
jbyte decrypt_buf [MAX_BUF] = {0};
jint last_decrypt_len = 8;

jint Java_com_google_android_gms_car_senderprotocol_SslWrapper_nativeDecryptionPipelineEnqueue (JNIEnv * env, jobject thiz, jobject bBuf, jint len) {           // Return len
  int retlen = -1;
  if (ena_log_verbo)
    logd ("DE Rx encrypted passed len: %d", len);

  if (neuter) {
    jbyte * buf = (jbyte *) (* env)->GetDirectBufferAddress (env, bBuf);// ByteBuffer must be created using an allocateDirect() factory method
    last_decrypt_len = len;
    if (len > MAX_BUF) {
      loge ("DecryptionPipelineEnqueue len too large");
      return (-1);
    }
    memcpy (decrypt_buf, buf, len);
    retlen = len;
    if (ena_log_verbo)
      logd ("DE Rx retlen: %d", retlen);
    return (retlen);
  }

  if (Java_com_google_android_gms_car_senderprotocol_SslWrapper_nativeDecryptionPipelineEnqueue_o)
    retlen = Java_com_google_android_gms_car_senderprotocol_SslWrapper_nativeDecryptionPipelineEnqueue_o (env, thiz, bBuf, len);
  else
    loge ("NO %s", __func__);
  if (ena_log_verbo)
    logd ("DE Rx retlen: %d", retlen);
  return (retlen);
}

jint Java_com_google_android_gms_car_senderprotocol_SslWrapper_nativeDecryptionPipelinePending  (JNIEnv * env, jobject thiz) {                                    // Return len
  int retlen = -1;
  if (neuter) {
    retlen = last_decrypt_len;
    if (ena_log_verbo)
      logd ("DP Rx pending retlen: %d", retlen);
    return (retlen);
  }

  if (Java_com_google_android_gms_car_senderprotocol_SslWrapper_nativeDecryptionPipelinePending_o)
    retlen = Java_com_google_android_gms_car_senderprotocol_SslWrapper_nativeDecryptionPipelinePending_o (env, thiz);
  else
    loge ("NO %s", __func__);
  if (ena_log_verbo)
    logd ("DP Rx pending retlen: %d", retlen);
  return (retlen);
}

jint Java_com_google_android_gms_car_senderprotocol_SslWrapper_nativeDecryptionPipelineDequeue (JNIEnv * env, jobject thiz, jobject bBuf, jint len) {           // Return len
  int retlen = -1;
  if (neuter) {
    if (len > MAX_BUF) {
      loge ("DecryptionPipelineDequeue len too large");
      return (-1);
    }
    jbyte * buf = (jbyte *) (* env)->GetDirectBufferAddress (env, bBuf);// ByteBuffer must be created using an allocateDirect() factory method
    retlen = last_decrypt_len;
    last_decrypt_len = 0;
    memcpy (buf, decrypt_buf, len);
    if (en_dump_data)
      logd_jbytebu (env, "rx: ", bBuf, 0, len, 1);
    if (ena_log_verbo)
      logd ("DD Rx decrypted len: %d  retlen: %d", len, retlen);

    return (len); // len is whatever we returned as pending
  }

  if (Java_com_google_android_gms_car_senderprotocol_SslWrapper_nativeDecryptionPipelineDequeue_o)
    retlen = Java_com_google_android_gms_car_senderprotocol_SslWrapper_nativeDecryptionPipelineDequeue_o (env, thiz, bBuf, len);
  else
    loge ("NO %s", __func__);
  if (en_dump_data)
    logd_jbytebu (env, "rx: ", bBuf, 0, retlen, 1);
  if (ena_log_verbo)
    logd ("DD Rx decrypted len: %d  retlen: %d", len, retlen);
  return (retlen);
}  

//jbyte encrypt_buf [MAX_BUF] = {0};

jint Java_com_google_android_gms_car_senderprotocol_SslWrapper_nativeEncryptionPipelineEnqueue  (JNIEnv * env, jobject thiz, jobject bBuf, jint idx, jint len) { // Return len
  int retlen = -1;
  if (en_dump_data)
    logd_jbytebu (env, "TX: ", bBuf, idx, len, 2);
  if (neuter) {
    jbyte * encrypt_buf = write_tail_buffer_get (len);
    if (ena_log_verbo)
      logd ("EE Tx encrypt_buf: %p", encrypt_buf);
    if (encrypt_buf == NULL) {
      return (0);
    }

    jbyte * buf = (jbyte *) (* env)->GetDirectBufferAddress (env, bBuf);// ByteBuffer must be created using an allocateDirect() factory method
    //logd ("EncryptionPipelineEnqueue buf: %p  idx: %d  len: %d", buf, idx, len);
    if (len > MAX_BUF) {
      loge ("EncryptionPipelineEnqueue len too large");
      return (-1);
    }
    memcpy (encrypt_buf, & buf [idx], len);
    if (en_dump_data && ena_log_verbo)
      hex_dump ("TX: ", 16, encrypt_buf, len);
    //logd_jbytebu (env, "Tx: ", bBuf, idx, len, 2);
    return (len);
  }

  if (Java_com_google_android_gms_car_senderprotocol_SslWrapper_nativeEncryptionPipelineEnqueue_o)
    retlen = Java_com_google_android_gms_car_senderprotocol_SslWrapper_nativeEncryptionPipelineEnqueue_o (env, thiz, bBuf, idx, len);
  else
    loge ("NO %s", __func__);
  if (ena_log_verbo)
    logd ("EE Tx retlen: %d", retlen);
  return (retlen);
}

jint Java_com_google_android_gms_car_senderprotocol_SslWrapper_nativeEncryptionPipelineDequeue (JNIEnv * env, jobject thiz, jobject bBuf, jint len) {           // Return len
  if (ena_log_verbo)
    logd ("ED Tx passed len: %d", len);
  if (neuter) {
    int retlen = -1;
    jbyte * encrypt_buf = read_head_buffer_get (& retlen);
    if (ena_log_verbo)
      logd ("ED Tx encrypt_buf: %p", encrypt_buf);
    if (encrypt_buf == NULL) {
      return (0);
    }

    jbyte * buf = (jbyte *) (* env)->GetDirectBufferAddress (env, bBuf);// ByteBuffer must be created using an allocateDirect() factory method
    //logd ("EncryptionPipelineDequeue buf: %p  len: %d", buf, len);
    if (len > MAX_BUF) {
      loge ("EncryptionPipelineDequeue len too large");
      return (-1);
    }
    memcpy (buf, encrypt_buf, retlen);
    if (ena_log_verbo)
      logd ("ED Tx encrypted retlen: %d", retlen);
    if (en_dump_data && ena_log_verbo)
      hex_dump ("ED Tx encrypt_buf: ", 16, encrypt_buf, retlen);
    return (retlen);
  }

  int retlen = -1;
  if (Java_com_google_android_gms_car_senderprotocol_SslWrapper_nativeEncryptionPipelineDequeue_o)
    retlen = Java_com_google_android_gms_car_senderprotocol_SslWrapper_nativeEncryptionPipelineDequeue_o (env, thiz, bBuf, len);
  else
    loge ("NO %s", __func__);
  if (ena_log_verbo)
    logd ("ED Tx encrypted retlen: %d", retlen);
  return (len);
}

