#include <stdio.h>
#include "uas_uti.h"
#include "uas_ssl.h"
#include "uas_aap.h"

int iaap_state = 0;

int uas_aap_stop() {
  iaap_state = uas_STATE_STOPPIN;
  int ret = uas_usb_stop();
  iaap_state = uas_STATE_STOPPED;

  return ret;
}

int uas_aap_usb_set (int chan, int flags, int type, byte * buf, int len) {
  buf [0] = (byte) chan;
  buf [1] = (byte) flags;
  buf [2] = (len -4) / 256;
  buf [3] = (len -4) % 256;
  if (type >= 0) {
    buf [4] = type / 256;
    buf [5] = type % 256;
  }

  return (len);
}

int uas_aap_usb_send (byte * buf, int len, int tmo) {
  if (iaap_state != uas_STATE_STARTED && iaap_state != uas_STATE_STARTIN) {
    return (-1);
  }
  int ret = uas_usb_send (buf, len, tmo);
  if (ret < 0 || ret != len) {
    uas_aap_stop (); 
    return (-1);
  }  
  return (ret);
}

int uas_aap_usb_recv (byte * buf, int len, int tmo) {
  int ret = 0;
  if (iaap_state != uas_STATE_STARTED && iaap_state != uas_STATE_STARTIN) {
    return (-1);
  }
  ret = uas_usb_recv (buf, len, tmo);
  if (ret < 0) {
    uas_aap_stop (); 
  }
  return (ret);
}

int uas_aap_start(byte ep_in_addr, byte ep_out_addr) {
  if (iaap_state == uas_STATE_STARTED) {
    return 0;
  }
  iaap_state = uas_STATE_STARTIN;
  int ret = uas_usb_start(ep_in_addr, ep_out_addr);

  if (ret) {
    iaap_state = uas_STATE_STOPPED;
    return ret;
  }

  byte vr_buf [] = {0, 3, 0, 6, 0, 1, 0, 1, 0, 1};
  ret = uas_aap_usb_set(0, 3, 1, vr_buf, sizeof(vr_buf));
  ret = uas_aap_usb_send(vr_buf, sizeof(vr_buf), 1000);

  if (ret < 0) {
    logd("Version request send ret: %d\n", ret);
    uas_aap_stop();
    return -1;
  }

  byte buf[DEFBUF] = {0};
  ret = uas_aap_usb_recv(buf, sizeof(buf), 1000);
  if (ret <= 0) {
    logd("Version response recv ret: %d\n", ret);
    uas_aap_stop();
    return -1;
  }
  logd("Version response recv ret: %d\n", ret);

  ret = uas_ssl_handshake();
  if (ret) {
    uas_aap_stop();
    return ret;
  }

  byte ac_buf[] = {0, 3, 0, 4, 0, 4, 8, 0};
  ret = uas_aap_usb_set(0, 3, 4, ac_buf, sizeof(ac_buf));
  ret = uas_aap_usb_send(ac_buf, sizeof(ac_buf), 1000);

  if (ret < 0) {
    logd("hu_aap_usb_send() ret: %d", ret);
    uas_aap_stop();
    return -1;
  }

  iaap_state = uas_STATE_STARTED;
  logd ("  SET: iaap_state: %d (%s)", iaap_state, state_get (iaap_state));

  return 0;
}
