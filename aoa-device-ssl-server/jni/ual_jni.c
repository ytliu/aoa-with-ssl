#include <jni.h>
#include <stdlib.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include "ual_uti.h"

#define UAL_SSL_INTERNAL
#include "ual_jni.h"

SSL_METHOD  * ual_ssl_method  = NULL;
SSL_CTX     * ual_ssl_ctx     = NULL;
SSL         * ual_ssl_ssl     = NULL;
BIO         * ual_ssl_rm_bio  = NULL;
BIO         * ual_ssl_wm_bio  = NULL;

#define DEFBUF  65536 // Default buffer size is maximum for USB

/* SSL debug */
#define SSL_WHERE_INFO(ssl, w, flag, msg) {                \
  if(w & flag) {                                         \
    logd("+ %s: %20.20s - %30.30s", name, msg, SSL_state_string_long(ssl)); \
  }                                                      \
} 

void ual_ssl_info_callback(const SSL* ssl, int where, int ret, const char* name) {

  if(ret == 0) {
    logd("-- ual_ssl_info_callback: error occured.\n");
    return;
  }

  SSL_WHERE_INFO(ssl, where, SSL_CB_LOOP, "LOOP");
  SSL_WHERE_INFO(ssl, where, SSL_CB_HANDSHAKE_START, "HANDSHAKE START");
  SSL_WHERE_INFO(ssl, where, SSL_CB_HANDSHAKE_DONE, "HANDSHAKE DONE");
}

void ual_ssl_server_info_callback(const SSL* ssl, int where, int ret) {
  ual_ssl_info_callback(ssl, where, ret, "server");
}

#undef UAL_LOG_FILE
#ifdef UAL_LOG_FILE
void ual_logfile (char * log_line) {
  int logfd = open ("/sdcard/uallog", O_RDWR | O_APPEND, S_IRWXU | S_IRWXG | S_IRWXO);
  int written = 0;
  if (logfd >= 0)
    written = write (logfd, log_line, strlen (log_line));
  close(logfd);
}
#endif


int jni_ssl_init() {
  int ret;
  BIO *cert_bio = NULL;
  BIO *pkey_bio = NULL;

  logd("in jni_ssl_init()\n");

  SSL_load_error_strings();
  SSL_library_init();
  ERR_load_BIO_strings();
  ERR_load_crypto_strings();
  ERR_load_SSL_strings();
  OPENSSL_add_all_algorithms_noconf();

  ret = RAND_status();
  logd("RAND_status ret: %d", ret);

#ifdef UAL_LOG_FILE
  ual_logfile(cert_buf);
#endif
  cert_bio = BIO_new_mem_buf(cert_buf, sizeof(cert_buf));
  pem_password_cb * ppcb1 = NULL;
  void * u1 = NULL;
  X509 * x509 = NULL;
  X509 * x509_cert = PEM_read_bio_X509_AUX(cert_bio, & x509, ppcb1, u1);
  if (x509_cert == NULL) {
    logd("read_bio_X509_AUX() error");
    return (-1);
  }
  logd("PEM_read_bio_X509_AUX() x509_cert: %p", x509_cert);
  ret = BIO_free(cert_bio);

#ifdef UAL_LOG_FILE
  ual_logfile(pkey_buf);
#endif
  pkey_bio = BIO_new_mem_buf(pkey_buf, sizeof(pkey_buf));
  pem_password_cb * ppcb2 = NULL;
  void * u2 = NULL;
  EVP_PKEY * priv_key_ret = NULL;
  EVP_PKEY * priv_key = PEM_read_bio_PrivateKey(pkey_bio, &priv_key_ret, ppcb2, u2);
  if (priv_key == NULL) {
    logd("PEM_read_bio_PrivateKey() error");
    return (-1);
  }
  logd("PEM_read_bio_PrivateKey() priv_key: %p", priv_key);
  ret = BIO_free(pkey_bio);

  ual_ssl_method = (SSL_METHOD *)TLSv1_2_server_method();
  if (ual_ssl_method == NULL) {
    logd("TLSv1_2_client_method() error");
    return (-1);
  }
  logd("TLSv1_2_server_method() ual_ssl_method: %p", ual_ssl_method);

  ual_ssl_ctx = SSL_CTX_new(ual_ssl_method);
  if (ual_ssl_ctx == NULL) {
    logd("SSL_CTX_new() error");
    return (-1);
  }
  logd("SSL_CTX_new() ual_ssl_ctx: %p", ual_ssl_ctx);

  ret = SSL_CTX_use_certificate(ual_ssl_ctx, x509_cert);
  logd("SSL_CTX_use_certificate() ret: %d", ret);

  ret = SSL_CTX_use_PrivateKey(ual_ssl_ctx, priv_key);
  logd("SSL_CTX_use_PrivateKey() ret: %d", ret);

  ual_ssl_ssl = SSL_new(ual_ssl_ctx);
  if (ual_ssl_ssl == NULL) {
    logd("SSL_new() failed");
    return (-1);
  }
  logd("SSL_new() ual_ssl_ssl: %p", ual_ssl_ssl);

  /* info callback */
  SSL_set_info_callback(ual_ssl_ssl, ual_ssl_server_info_callback);

  ret = SSL_check_private_key(ual_ssl_ssl);
  if (ret != 1) {
    logd("SSL_check_private_key() failed ret: %d", ret);
    return (-1);
  }
  logd("SSL_check_private_key() ret: %d", ret);

  ual_ssl_rm_bio = BIO_new(BIO_s_mem());
  if (ual_ssl_rm_bio == NULL) {
    logd("BIO_new() ual_ssl_rm_bio failed");
    return (-1);
  }
  logd("BIO_new() ual_ssl_rm_bio: %p", ual_ssl_rm_bio);

  ual_ssl_wm_bio = BIO_new(BIO_s_mem());
  if (ual_ssl_wm_bio == NULL) {
    logd("BIO_new() ual_ssl_wm_bio failed");
    return (-1);
  }
  logd("BIO_new() ual_ssl_wm_bio: %p", ual_ssl_wm_bio);

  SSL_set_verify(ual_ssl_ssl, SSL_VERIFY_NONE, NULL);
  
  SSL_set_bio(ual_ssl_ssl, ual_ssl_rm_bio, ual_ssl_wm_bio);

  BIO_set_write_buf_size(ual_ssl_rm_bio, DEFBUF);
  BIO_set_write_buf_size(ual_ssl_wm_bio, DEFBUF);
  
  SSL_set_accept_state(ual_ssl_ssl); // Set ssl to work in server mode
  logd("SSL state: 0x%x", ual_ssl_ssl->state);

  return 0;
}

int jni_ssl_hs_data_enqueue(int len, char *buf) {
  int ret = 0;
  ret = BIO_write(ual_ssl_rm_bio, &buf[2], len - 2);
  if (ret <= 0) {
    logd ("BIO_write() client req failed ret: %d", ret);
    return (-1);
  }
  logd ("BIO_write() client req ret: %d", ret);
  return ret; 
}

int jni_ssl_hs_data_dequeue(char *buf) {
  int ret = 0;
  ret = BIO_read(ual_ssl_wm_bio, buf, DEFBUF - 6);
  if (ret <= 0) {
    logd ("BIO_read() server rsp failed ret: %d", ret);
    return (-1);
  }
  logd ("BIO_read() server rsp ret: %d", ret);

  return (ret);
}

void ual_ssl_inf_log () {

  const char *ssl_state_string_long = SSL_state_string_long(ual_ssl_ssl);
  logd("ssl_state_string_long: 0x%x %s\n", ual_ssl_ssl->state, ssl_state_string_long);

  const char *ssl_version = SSL_get_version(ual_ssl_ssl);
  logd("ssl_version: %s\n", ssl_version);

  const SSL_CIPHER *ssl_cipher = SSL_get_current_cipher(ual_ssl_ssl);
  const char *ssl_cipher_name = SSL_CIPHER_get_name(ssl_cipher);
  logd("ssl_cipher_name: %s\n", ssl_cipher_name);
}

void ual_ssl_ret_log (int ret) {
  int ssl_err = SSL_get_error(ual_ssl_ssl, ret);
  char *err_str = "";

  switch (ssl_err) {
    case SSL_ERROR_NONE:              err_str = ("");                      break;
    case SSL_ERROR_ZERO_RETURN:       err_str = ("Error Zero Return");     break;
    case SSL_ERROR_WANT_READ:         err_str = ("Error Want Read");       break;
    case SSL_ERROR_WANT_WRITE:        err_str = ("Error Want Write");      break;
    case SSL_ERROR_WANT_CONNECT:      err_str = ("Error Want Connect");    break;
    case SSL_ERROR_WANT_ACCEPT:       err_str = ("Error Want Accept");     break;
    case SSL_ERROR_WANT_X509_LOOKUP:  err_str = ("Error Want X509 Lookup");break;
    case SSL_ERROR_SYSCALL:           err_str = ("Error Syscall");         break;
    case SSL_ERROR_SSL:               err_str = ("Error SSL");             break;
    default:                          err_str = ("Error Unknown");         break;
  }

  if (strlen(err_str) == 0)
    logd("ret: %d  ssl_err: %d (Success)\n", ret, ssl_err);
  else
    logd("ret: %d  ssl_err: %d (%s)\n", ret, ssl_err, err_str);
}

void jni_ssl_handshake(int hs_ctr) {
  int ret = 0;
  ual_ssl_inf_log();
  ret = SSL_do_handshake(ual_ssl_ssl); 
  ual_ssl_inf_log();
  logd("SSL_do_handshake() ret: %d  hs_ctr: %d\n", ret, hs_ctr);

  if (SSL_get_error(ual_ssl_ssl, ret) != SSL_ERROR_WANT_READ) {
    ual_ssl_ret_log(ret);
    ual_ssl_inf_log();
  }
}

int jni_ssl_encrypt_data(int len, char *plain_buf, char *cipher_buf) {
  int bytes_written = 0;
  int bytes_read = 0;
  
  bytes_written = SSL_write(ual_ssl_ssl, plain_buf, len);
  if (bytes_written < 0) {
    logd("SSL_write failed: %d", bytes_written);
    ual_ssl_ret_log(bytes_written);
    ual_ssl_inf_log();
  }
  bytes_read = BIO_read(ual_ssl_wm_bio, cipher_buf, DEFBUF);
  if (bytes_read < 0) {
    logd("BIO_read failed: %d", bytes_read);
  }
  return (bytes_read); 
}

int jni_ssl_decrypt_data(int len, char *cipher_buf, char *plain_buf) {
  int bytes_written = 0;
  int bytes_read = 0;
  
  bytes_written = BIO_write(ual_ssl_rm_bio, cipher_buf, len);
  if (bytes_written < 0) {
    logd("BIO_write failed: %d", bytes_written);
  }
  bytes_read = SSL_read(ual_ssl_ssl, plain_buf, DEFBUF);
  if (bytes_read < 0) {
    logd("SSL_read failed: %d", bytes_read);
    ual_ssl_ret_log(bytes_read);
    ual_ssl_inf_log();
  }
  return (bytes_read);
}

JNIEXPORT jint Java_cn_sjtu_ipads_ual_UalTraActivity_nativeInit(JNIEnv *env, jobject thiz) {
  int ret = jni_ssl_init();
  return (ret);
}

JNIEXPORT void Java_cn_sjtu_ipads_ual_UalTraActivity_nativeHandshakeDataEnqueue(JNIEnv *env, jobject thiz, jint buf_len, jbyteArray buf) {
  jbyte *jni_buf = NULL;
  jni_buf = (*env)->GetByteArrayElements(env, buf, NULL);
  jni_ssl_hs_data_enqueue(buf_len, jni_buf);
}

JNIEXPORT void Java_cn_sjtu_ipads_ual_UalTraActivity_nativeHandshake(JNIEnv *env, jobject thiz, jint hs_ctr) {
  jni_ssl_handshake(hs_ctr);
}

JNIEXPORT jint Java_cn_sjtu_ipads_ual_UalTraActivity_nativeHandshakeDataDequeue(JNIEnv *env, jobject thiz, jbyteArray buf) {
  int len = 0; 
  jbyte *jni_buf = NULL;
  jni_buf = (*env)->GetByteArrayElements(env, buf, NULL);
  len = jni_ssl_hs_data_dequeue(jni_buf);

  return (len);
}

JNIEXPORT jint Java_cn_sjtu_ipads_ual_UalTraActivity_nativeEncryptData(JNIEnv *env, jobject thiz, jint len, jbyteArray src_buf, jbyteArray res_buf) {
  int ret = 0; 
  jbyte *plain_buf = NULL;
  jbyte *cipher_buf = NULL;
  plain_buf = (*env)->GetByteArrayElements(env, src_buf, NULL);
  cipher_buf = (*env)->GetByteArrayElements(env, res_buf, NULL);
  ret = jni_ssl_encrypt_data(len, plain_buf, cipher_buf);

  return (ret);
}

JNIEXPORT jint Java_cn_sjtu_ipads_ual_UalTraActivity_nativeDecryptData(JNIEnv *env, jobject thiz, jint len, jbyteArray src_buf, jbyteArray res_buf) {
  int ret = 0; 
  jbyte *cipher_buf = NULL;
  jbyte *plain_buf = NULL;
  cipher_buf = (*env)->GetByteArrayElements(env, src_buf, NULL);
  plain_buf = (*env)->GetByteArrayElements(env, res_buf, NULL);
  ret = jni_ssl_decrypt_data(len, cipher_buf, plain_buf);

  return (ret);
}
