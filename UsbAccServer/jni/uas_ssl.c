
#include "uas_uti.h"
#include "uas_aap.h"

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

SSL_METHOD  * uas_ssl_method  = NULL;
SSL_CTX     * uas_ssl_ctx     = NULL;
SSL         * uas_ssl_ssl     = NULL;
BIO         * uas_ssl_rm_bio  = NULL;
BIO         * uas_ssl_wm_bio  = NULL;

#define MR_SSL_INTERNAL   // For certificate and private key only
#include "uas_ssl.h"


void uas_ssl_inf_log () {

  const char * ssl_state_string_long = SSL_state_string_long (uas_ssl_ssl);
  logd("ssl_state_string_long: %s\n", ssl_state_string_long);

  const char * ssl_version = SSL_get_version (uas_ssl_ssl);
  logd("ssl_version: %s\n", ssl_version);

  const SSL_CIPHER * ssl_cipher = SSL_get_current_cipher (uas_ssl_ssl);
  const char * ssl_cipher_name = SSL_CIPHER_get_name (ssl_cipher);
  logd("ssl_cipher_name: %s\n", ssl_cipher_name);
}

void uas_ssl_ret_log (int ret) {
  int ssl_err = SSL_get_error (uas_ssl_ssl, ret);
  char * err_str = "";

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

  if (strlen (err_str) == 0)
    logd("ret: %d  ssl_err: %d (Success)\n", ret, ssl_err);
  else
    logd("ret: %d  ssl_err: %d (%s)\n", ret, ssl_err, err_str);
}

int uas_ssl_handshake () {

  int                 ret;
  BIO               * cert_bio = NULL;
  BIO               * pkey_bio = NULL;

  ret = SSL_library_init ();                                          // Init
  if (ret != 1) {
    return (-1);
  }

  SSL_load_error_strings ();
  ERR_load_BIO_strings ();
  ERR_load_crypto_strings ();
  ERR_load_SSL_strings ();

  OPENSSL_add_all_algorithms_noconf ();

  ret = RAND_status ();
  if (ret != 1) {
    return (-1);
  }

  cert_bio = BIO_new_mem_buf (cert_buf, sizeof (cert_buf));
  pem_password_cb * ppcb1 = NULL;
  void * u1 = NULL;
  X509 * x509 = NULL;
  X509 * x509_cert = PEM_read_bio_X509_AUX (cert_bio, & x509, ppcb1, u1);
  if (x509_cert == NULL) {
    return (-1);
  }
  ret = BIO_free (cert_bio);

  pkey_bio = BIO_new_mem_buf (pkey_buf, sizeof (pkey_buf));
  pem_password_cb * ppcb2 = NULL;
  void * u2 = NULL;
  EVP_PKEY * priv_key_ret = NULL;
  EVP_PKEY * priv_key = PEM_read_bio_PrivateKey (pkey_bio, & priv_key_ret, ppcb2, u2);
  if (priv_key == NULL) {
    return (-1);
  }
  ret = BIO_free (pkey_bio);

  uas_ssl_method = (SSL_METHOD *) TLSv1_2_client_method ();
  if (uas_ssl_method == NULL) {
    return (-1);
  }

  uas_ssl_ctx = SSL_CTX_new (uas_ssl_method);
  if (uas_ssl_ctx == NULL) {
    return (-1);
  }

  ret = SSL_CTX_use_certificate (uas_ssl_ctx, x509_cert);
  logd("SSL_CTX_use_certificate() ret: %d\n", ret);

  ret = SSL_CTX_use_PrivateKey (uas_ssl_ctx, priv_key);
  logd("SSL_CTX_use_PrivateKey() ret: %d\n", ret);
  
  uas_ssl_ssl = SSL_new (uas_ssl_ctx);
  if (uas_ssl_ssl == NULL) {
    return (-1);
  }

  ret = SSL_check_private_key (uas_ssl_ssl);
  if (ret != 1) {
    return (-1);
  }

  uas_ssl_rm_bio = BIO_new (BIO_s_mem ());
  if (uas_ssl_rm_bio == NULL) {
    return (-1);
  }

  uas_ssl_wm_bio = BIO_new (BIO_s_mem ());
  if (uas_ssl_wm_bio == NULL) {
    return (-1);
  }

  SSL_set_bio (uas_ssl_ssl, uas_ssl_rm_bio, uas_ssl_wm_bio);
  BIO_set_write_buf_size (uas_ssl_rm_bio, DEFBUF);
  BIO_set_write_buf_size (uas_ssl_wm_bio, DEFBUF);

  SSL_set_connect_state (uas_ssl_ssl);

  SSL_set_verify (uas_ssl_ssl, SSL_VERIFY_NONE, NULL);

  byte hs_buf [DEFBUF] = {0};
  int hs_ctr  = 0;

  int hs_finished = 0;

  while (! hs_finished && hs_ctr ++ < 2) {

    ret = SSL_do_handshake (uas_ssl_ssl);
    logd("SSL_do_handshake() ret: %d  hs_ctr: %d\n", ret, hs_ctr);

    if (ena_log_verbo || SSL_get_error (uas_ssl_ssl, ret) != SSL_ERROR_WANT_READ) {
      uas_ssl_ret_log (ret);
      uas_ssl_inf_log ();
    }

    ret = BIO_read (uas_ssl_wm_bio, & hs_buf [6], sizeof (hs_buf) - 6); // Read from the BIO Client request: Hello/Key Exchange
    if (ret <= 0) {
      logd("BIO_read() HS client req ret: %d", ret);
      return (-1);
    }
    logd("BIO_read() HS client req ret: %d", ret);
    int len = ret + 6;
    ret = uas_aap_usb_set (0, 3, 3, hs_buf, len);
    ret = uas_aap_usb_send (hs_buf, len, 1000); // Send Client request to AA Server
    if (ret <= 0 || ret != len) {
      logd("uas_aap_usb_send() HS client req ret: %d  len: %d\n", ret, len);
    }      

    ret = uas_aap_usb_recv (hs_buf, sizeof (hs_buf), 1000); // Get Rx packet from USB: Receive Server response: Hello/Change Cipher
    if (ret <= 0) { // If error, then done w/ error
      logd("HS server rsp ret: %d\n", ret);
      return (-1);
    }  
    logd("HS server rsp ret: %d", ret);

    ret = BIO_write (uas_ssl_rm_bio, & hs_buf [6], ret - 6); // Write to the BIO Server response
    
    ms_sleep (3000);
    
    if (ret <= 0) {
      logd ("BIO_write() server rsp ret: %d", ret);
      return (-1);
    }
    logd ("BIO_write() server rsp ret: %d", ret);
  }

  hs_finished = 1;

  if (! hs_finished) {
    logd("Handshake did not finish !!!!\n");
    return (-1);
  }

  return (0);

}
