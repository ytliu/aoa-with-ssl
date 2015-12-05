#include <stdio.h>
#include "uas_uti.h"
#include "uas_oap.h"

#include <libusb.h>

int iusb_state = 0; // 0: Initial    1: Startin    2: Started    3: Stoppin    4: Stopped

#ifndef LIBUSB_LOG_LEVEL_NONE
#define LIBUSB_LOG_LEVEL_NONE    0
#endif
#ifndef LIBUSB_LOG_LEVEL_ERROR
#define LIBUSB_LOG_LEVEL_ERROR   1
#endif
#ifndef LIBUSB_LOG_LEVEL_WARNING
#define LIBUSB_LOG_LEVEL_WARNING 2
#endif
#ifndef LIBUSB_LOG_LEVEL_INFO
#define LIBUSB_LOG_LEVEL_INFO    3
#endif
#ifndef LIBUSB_LOG_LEVEL_DEBUG
#define LIBUSB_LOG_LEVEL_DEBUG   3
#endif

struct libusb_device_handle *iusb_dev_hndl = NULL;
libusb_device *iusb_best_device = NULL;
int   iusb_ep_in          = -1;
int   iusb_ep_out         = -1;

int   iusb_best_vendor    = 0;
int   iusb_best_product   = 0;
byte  iusb_curr_man [256] = {0};
byte  iusb_best_man [256] = {0};
byte  iusb_curr_pro [256] = {0};
byte  iusb_best_pro [256] = {0};

char *iusb_error_get (int error) {
  switch (error) {
    case LIBUSB_SUCCESS:                                              // 0
      return ("LIBUSB_SUCCESS");
    case LIBUSB_ERROR_IO:                                             // -1
      return ("LIBUSB_ERROR_IO");
    case LIBUSB_ERROR_INVALID_PARAM:                                  // -2
      return ("LIBUSB_ERROR_INVALID_PARAM");
    case LIBUSB_ERROR_ACCESS:                                         // -3
      return ("LIBUSB_ERROR_ACCESS");
    case LIBUSB_ERROR_NO_DEVICE:                                      // -4
      return ("LIBUSB_ERROR_NO_DEVICE");
    case LIBUSB_ERROR_NOT_FOUND:                                      // -5
      return ("LIBUSB_ERROR_NOT_FOUND");
    case LIBUSB_ERROR_BUSY:                                           // -6
      return ("LIBUSB_ERROR_BUSY");
    case LIBUSB_ERROR_TIMEOUT:                                        // -7
      return ("LIBUSB_ERROR_TIMEOUT");
    case LIBUSB_ERROR_OVERFLOW:                                       // -8
      return ("LIBUSB_ERROR_OVERFLOW");
    case LIBUSB_ERROR_PIPE:                                           // -9
      return ("LIBUSB_ERROR_PIPE");
    case LIBUSB_ERROR_INTERRUPTED:                                    // -10
      return ("Error:LIBUSB_ERROR_INTERRUPTED");
    case LIBUSB_ERROR_NO_MEM:                                         // -11
      return ("LIBUSB_ERROR_NO_MEM");
    case LIBUSB_ERROR_NOT_SUPPORTED:                                  // -12
      return ("LIBUSB_ERROR_NOT_SUPPORTED");
    case LIBUSB_ERROR_OTHER:                                          // -99
      return ("LIBUSB_ERROR_OTHER");
  }
  return ("LIBUSB_ERROR Unknown error");//: %d", error);
}

int iusb_bulk_transfer (int ep, byte * buf, int len, int tmo) {
  char *dir = "recv";
  if (ep == iusb_ep_out)
    dir = "send";

  if (iusb_state != uas_STATE_STARTED) {
    return (-1);
  }

  int usb_err = -2;
  int total_bytes_xfrd = 0;
  int bytes_xfrd = 0;

  errno = 0;
  int continue_transfer = 1;
  while (continue_transfer) {
    usb_err = libusb_bulk_transfer (iusb_dev_hndl, ep, buf, len, & bytes_xfrd, tmo);

    continue_transfer = 0;
    if (bytes_xfrd > 0)
      total_bytes_xfrd += bytes_xfrd;

    if (bytes_xfrd > 0 && usb_err == LIBUSB_ERROR_TIMEOUT) {
      continue_transfer = 1;
      buf += bytes_xfrd;
      len -= bytes_xfrd;
    }
    
    bytes_xfrd = 0;
  }

  if (total_bytes_xfrd <= 0 && usb_err < 0) {
    if (errno == EAGAIN || errno == ETIMEDOUT || usb_err == LIBUSB_ERROR_TIMEOUT)
      return (0);

    uas_usb_stop ();
    return (-1);
  }

  return (total_bytes_xfrd);
}

int uas_usb_recv (byte *buf, int len, int tmo) {
  int ret = iusb_bulk_transfer (iusb_ep_in, buf, len, tmo);       // milli-second timeout
  return (ret);
}

int uas_usb_send (byte *buf, int len, int tmo) {
  int ret = iusb_bulk_transfer (iusb_ep_out, buf, len, tmo);      // milli-second timeout
  return (ret);
}

int iusb_control_transfer (libusb_device_handle * usb_hndl, uint8_t req_type, uint8_t req_val, uint16_t val, uint16_t idx, byte * buf, uint16_t len, unsigned int tmo) {

  int usb_err = libusb_control_transfer (usb_hndl, req_type, req_val, val, idx, buf, len, tmo);
  if (usb_err < 0) {
    return (-1);
  }
  return (0);
}


int iusb_oap_start () {
  byte oap_protocol_data [2] = {0, 0};
  int oap_protocol_level   = 0;

  uint8_t       req_type= USB_SETUP_DEVICE_TO_HOST | USB_SETUP_TYPE_VENDOR | USB_SETUP_RECIPIENT_DEVICE;
  uint8_t       req_val = ACC_REQ_GET_PROTOCOL;
  uint16_t      val     = 0;
  uint16_t      idx     = 0;
  byte *        data    = oap_protocol_data;
  uint16_t      len     = sizeof (oap_protocol_data);
  unsigned int  tmo     = 1000;
  // Get OAP Protocol level
  val = 0;
  idx = 0;
  int usb_err = iusb_control_transfer (iusb_dev_hndl, req_type, req_val, val, idx, data, len, tmo);
  if (usb_err != 0) {
    logd("Done iusb_control_transfer usb_err: %d (%s)", usb_err, iusb_error_get (usb_err));
    return (-1);
  }

  logd("Done iusb_control_transfer usb_err: %d (%s)\n", usb_err, iusb_error_get (usb_err));

  oap_protocol_level = data [1] << 8 | data [0];
  if (oap_protocol_level < 2) {
    logd("Error oap_protocol_level: %d", oap_protocol_level);
    return (-1);
  }
  logd("oap_protocol_level: %d\n", oap_protocol_level);

  req_type = USB_SETUP_HOST_TO_DEVICE | USB_SETUP_TYPE_VENDOR | USB_SETUP_RECIPIENT_DEVICE;
  req_val = ACC_REQ_SEND_STRING;

  char AAP_VAL_MAN [31] = "Android";
  char AAP_VAL_MOD [97] = "Android Auto";

  int garb = -1;
  iusb_control_transfer (iusb_dev_hndl, req_type, req_val, val, ACC_IDX_MAN, AAP_VAL_MAN, strlen (AAP_VAL_MAN) + 1, tmo);
  iusb_control_transfer (iusb_dev_hndl, req_type, req_val, val, ACC_IDX_MOD, AAP_VAL_MOD, strlen (AAP_VAL_MOD) + 1, tmo);

  req_val = ACC_REQ_START;
  val = 0;
  idx = 0;
  if (iusb_control_transfer (iusb_dev_hndl, req_type, req_val, val, idx, NULL, 0, tmo) < 0) {
    logd("Error Accessory mode start request sent\n");
    return (-1);
  }
  logd("OK Accessory mode start request sent\n");

  return (0);
}

int iusb_vendor_get (libusb_device *device) {
  if (device == NULL)
    return (0);

  struct libusb_device_descriptor desc = {0};

  int usb_err = libusb_get_device_descriptor (device, & desc);
  if (usb_err != 0) {
    logd("Error usb_err: %d (%s)\n", usb_err, iusb_error_get (usb_err));
    return (0);
  }
  uint16_t vendor  = desc.idVendor;
  uint16_t product = desc.idProduct;
  logd("Done usb_err: %d  vendor:product = 0x%04x:0x%04x\n", usb_err, vendor, product);
  return (vendor);
}

int iusb_vendor_priority_get (int vendor) {
  if (vendor == USB_VID_GOO)
    return (10);
  if (vendor == USB_VID_HTC)
    return (9);
  if (vendor == USB_VID_MOT)
    return (8);
  if (vendor == USB_VID_SAM)
    return (7);
  if (vendor == USB_VID_SON)
    return (6);
  if (vendor == USB_VID_LGE)
    return (5);
  if (vendor == USB_VID_O1A)
    return (4);
  if (vendor == USB_VID_QUA)
    return (3);
  if (vendor == USB_VID_LIN)
    return (2);
  return (0);
}


int iusb_init (byte ep_in_addr, byte ep_out_addr) {
  logd("ep_in_addr: %d  ep_out_addr: %d\n", ep_in_addr, ep_out_addr);

  iusb_ep_in  = -1;
  iusb_ep_out = -1;
  iusb_best_device = NULL;
  iusb_best_vendor = 0;

  int usb_err = libusb_init (NULL);
  if (usb_err < 0) {
    logd("Error libusb_init usb_err: %d (%s)\n", usb_err, iusb_error_get (usb_err));
    return (-1);
  }

  libusb_set_debug (NULL, LIBUSB_LOG_LEVEL_WARNING);

  libusb_device ** list;
  usb_err = libusb_get_device_list (NULL, & list);                // Get list of USB devices
  if (usb_err < 0) {
    return (-1);
  }
  ssize_t cnt = usb_err;
  int idx = 0;
  int iusb_best_vendor_priority = 0;

  libusb_device * device;
  for (idx = 0; idx < cnt; idx ++) {                                  // For all USB devices...
    device = list [idx];
    int vendor = iusb_vendor_get (device);
    if (vendor) {
      int vendor_priority = iusb_vendor_priority_get (vendor);
      if (iusb_best_vendor_priority <= vendor_priority) {  // For last
        iusb_best_vendor_priority = vendor_priority;
        iusb_best_vendor = vendor;
        iusb_best_device = device;
        strncpy (iusb_best_man, iusb_curr_man, sizeof (iusb_best_man));
        strncpy (iusb_best_pro, iusb_curr_pro, sizeof (iusb_best_pro));
      }
    }
  }
  if (iusb_best_vendor == 0 || iusb_best_device == NULL) {
    libusb_free_device_list (list, 1);
    return (-1);
  }


  usb_err = libusb_open (iusb_best_device, & iusb_dev_hndl);

  libusb_free_device_list (list, 1);

  if (usb_err != 0) {
    return (-1);
  }
  logd("Done libusb_open iusb_dev_hndl: %p\n", iusb_dev_hndl);

  usb_err = libusb_claim_interface (iusb_dev_hndl, 0);

  struct libusb_config_descriptor * config = NULL;
  usb_err = libusb_get_config_descriptor (iusb_best_device, 0, & config);
  if (usb_err != 0) {
    iusb_ep_in  = ep_in_addr;
    iusb_ep_out = ep_out_addr;
    return (0);
  }

  int num_int = config->bNumInterfaces;

  const struct libusb_interface            * inter;
  const struct libusb_interface_descriptor * interdesc;
  const struct libusb_endpoint_descriptor  * epdesc;

  for (idx = 0; idx < num_int; idx ++) {
    inter = & config->interface [idx];
    int num_altsetting = inter->num_altsetting;
    int j = 0;
    for (j = 0; j < inter->num_altsetting; j ++) { // For all alternate settings...
      interdesc = & inter->altsetting [j];
      int num_int = interdesc->bInterfaceNumber;
      int num_eps = interdesc->bNumEndpoints;
      int k = 0;
      for (k = 0; k < num_eps; k ++) { // For all endpoints...
        epdesc = & interdesc->endpoint [k];
        if (epdesc->bDescriptorType == LIBUSB_DT_ENDPOINT) {
          if ((epdesc->bmAttributes & LIBUSB_TRANSFER_TYPE_MASK) == LIBUSB_TRANSFER_TYPE_BULK) {
            int ep_add = epdesc->bEndpointAddress;
            if (ep_add & LIBUSB_ENDPOINT_DIR_MASK) {
              if (iusb_ep_in < 0) {
                iusb_ep_in = ep_add;
              }
            }
            else {
              if (iusb_ep_out < 0) {
                iusb_ep_out = ep_add;
              }
            }
            if (iusb_ep_in > 0 && iusb_ep_out > 0) { // If we have both endpoints now...
              libusb_free_config_descriptor (config);
              return (0);
            }
          }
        }
      }
    }
  }
  libusb_free_config_descriptor (config);

  if (iusb_ep_in == -1)
    iusb_ep_in  = ep_in_addr;
  if (iusb_ep_out == -1)
    iusb_ep_out = ep_out_addr;

  if (iusb_ep_in == -1 || iusb_ep_out == -1)
    return (-1);

  return (0);
}

int iusb_deinit () {

  if (iusb_dev_hndl == NULL) {
    return (-1);
  }

  int usb_err = libusb_release_interface (iusb_dev_hndl, 0);
  if (usb_err != 0)
    logd("Done libusb_release_interface usb_err: %d (%s)\n", usb_err, iusb_error_get (usb_err));
  else
    logd("Done libusb_release_interface usb_err: %d (%s)\n", usb_err, iusb_error_get (usb_err));

  libusb_close (iusb_dev_hndl);
  iusb_dev_hndl = NULL;

  libusb_exit (NULL); // Put here or can get a crash from pulling cable

  logd("Done\n");

  return (0);
}

int uas_usb_stop() {
  iusb_state = uas_STATE_STOPPIN;
  int ret = iusb_deinit();
  iusb_state = uas_STATE_STOPPED;
  return ret;
}

int uas_usb_start (byte ep_in_addr, byte ep_out_addr) {
  int ret = 0;

  if (iusb_state == uas_STATE_STARTED) {
    return (0);
  }

  iusb_state = uas_STATE_STARTIN;

  iusb_best_vendor = 0;
  int tries = 0;
  while (iusb_best_vendor != USB_VID_GOO && tries ++ < 4) {

    ret = iusb_init (ep_in_addr, ep_out_addr);
    if (ret < 0) {
      iusb_deinit ();
      iusb_state = uas_STATE_STOPPED;
      return (-1);
    }
    logd("OK iusb_init\n");

    if (iusb_best_vendor == USB_VID_GOO) {
      logd("Already OAP/AA mode, no need to call iusb_oap_start()\n");

      iusb_state = uas_STATE_STARTED;
      logd("  SET: iusb_state: %d\n", iusb_state);
      return (0);
    }

    ret = iusb_oap_start ();
    if (ret < 0) {
      iusb_deinit ();
      iusb_state = uas_STATE_STOPPED;
      return (-2);
    }
    logd("OK iusb_oap_start\n");

    if (iusb_best_vendor != USB_VID_GOO) {
      iusb_deinit ();
    }
    else
      logd("Done iusb_best_vendor == USB_VID_GOO\n");
  }

  if (iusb_best_vendor != USB_VID_GOO) {
    iusb_deinit ();
    iusb_state = uas_STATE_STOPPED;
    return (-3);
  }

  iusb_state = uas_STATE_STARTED;
  return (0);
}
