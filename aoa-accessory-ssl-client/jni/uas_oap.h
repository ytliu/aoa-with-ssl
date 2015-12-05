#define ACC_IDX_MAN   0   // Manufacturer
#define ACC_IDX_MOD   1   // Model

#define ACC_REQ_GET_PROTOCOL        51
#define ACC_REQ_SEND_STRING         52
#define ACC_REQ_START               53

#define ACC_REQ_AUDIO               58

#define USB_SETUP_HOST_TO_DEVICE 0x00 // transfer direction - host to device transfer = USB_DIR_OUT (Output from host)
#define USB_SETUP_DEVICE_TO_HOST 0x80 // transfer direction - device to host transfer = USB_DIR_IN  (Input to host)

#define USB_SETUP_TYPE_VENDOR                   0x40    // type - vendor   = USB_TYPE_VENDOR

#define USB_SETUP_RECIPIENT_DEVICE              0x00    // recipient - device

