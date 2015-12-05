int uas_aap_usb_recv(byte *buf, int len, int tmo);
int uas_aap_usb_set(int chan, int flags, int type, byte *buf, int len);
int uas_aap_usb_send(byte *buf, int len, int tmo);
int uas_aap_stop();
int uas_aap_start(byte ep_in_addr, byte ep_out_addr);
