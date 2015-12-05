package cn.sjtu.ipads;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.hardware.usb.UsbConstants;
import android.hardware.usb.UsbDeviceConnection;
import android.hardware.usb.UsbEndpoint;
import android.hardware.usb.UsbInterface;
import android.hardware.usb.UsbManager;
import android.hardware.usb.UsbDevice;
import android.util.Log;

import java.util.Map;

/**
 * Created by ytliu on 10/10/15.
 */
public class UasTransport {

  private Context m_context;
  private UasActivity m_uas_act;
  private UsbManager m_usb_mgr;
  private usb_receiver m_usb_receiver;
  private boolean m_usb_connected;
  private UsbDevice m_usb_device;

  private UsbDeviceConnection m_usb_dev_conn = null;
  private UsbEndpoint m_usb_ep_in = null;
  private UsbEndpoint m_usb_ep_out = null;
  private UsbInterface m_usb_iface = null;

  private int m_ep_in_addr = -1;
  private int m_ep_out_addr = -1;

  private static final int USB_VID_GOO = 0x18D1;
  private static final int USB_PID_OAP_NUL = 0x2D00;
  private static final int USB_PID_OAP_ADB = 0x2D01;

  private static final int OAP_STR_MANUFACTURE = 0;
  private static final int OAP_STR_MODEL = 1;
  private static final int OAP_GET_PROTOCOL = 51;
  private static final int OAP_SEND_STRING = 52;
  private static final int OAP_START = 53;

  static {
    System.loadLibrary("uas_jni");
  }

  private static native int native_aa_cmd(int cmd_len, byte[] cmd_buf, int res_len, byte[] res_buf);

  static final String TAG = "UAS_TRA";
  public static String str_uas_perm = "sjtu.ipads.ytliu.uas.ACTION_USB_DEVICE_PERMISSION";

  public UasTransport(UasActivity uas_act) {
    m_uas_act = uas_act;
    m_context = (Context)uas_act;
    m_usb_mgr = (UsbManager)m_context.getSystemService(Context.USB_SERVICE);

  }

  private int usb_open(UsbDevice device) {
    try {
      if (m_usb_dev_conn == null) {
        m_usb_dev_conn = m_usb_mgr.openDevice(device);
      }
      m_usb_iface = device.getInterface(0);
    } catch (Throwable e) {
      Log.d(TAG, "Throwable: " + e);
    }

    if (m_usb_dev_conn == null) {
      return -1;
    }
    return 0;
  }

  private void usb_close() {
    m_usb_ep_in = null;
    m_usb_ep_out = null;

    if (m_usb_dev_conn != null) {
      if (m_usb_iface != null) {
        m_usb_dev_conn.releaseInterface(m_usb_iface);
      }
      m_usb_dev_conn.close();
    }

    m_usb_dev_conn = null;
    m_usb_iface = null;

  }

  private void usb_disconnect() {
    m_usb_connected = false;
    m_usb_dev_conn = null;

    usb_close();
  }

  private int usb_acc_version_get(UsbDeviceConnection connection) {
    byte buffer[] = new byte[2];
    int len = connection.controlTransfer(UsbConstants.USB_DIR_IN | UsbConstants.USB_TYPE_VENDOR, OAP_GET_PROTOCOL, 0, 0, buffer, 2, 10000);
    if (len != 2) {
      return -1;
    }
    int oap_version = (buffer[1] << 8) | buffer[0];
    return oap_version;
  }

  private void usb_acc_string_send(UsbDeviceConnection connection, int index, String string) {
    byte[] buffer = (string + "\0").getBytes();
    int len = connection.controlTransfer(UsbConstants.USB_DIR_OUT | UsbConstants.USB_TYPE_VENDOR,
        OAP_SEND_STRING, 0, index, buffer, buffer.length, 10000);
  }

  private void usb_acc_strings_send() {
    usb_acc_string_send(m_usb_dev_conn, OAP_STR_MANUFACTURE, "Android");
    usb_acc_string_send(m_usb_dev_conn, OAP_STR_MODEL, "Android Auto");
  }

  private int acc_mode_connect() {
    int acc_ver = usb_acc_version_get(m_usb_dev_conn);

    m_usb_ep_in = null;
    m_usb_ep_out = null;
    m_ep_in_addr = -1;
    m_ep_out_addr = -1;

    for (int i = 0; i < m_usb_iface.getEndpointCount(); i++) {
      UsbEndpoint ep = m_usb_iface.getEndpoint(i);
      if (ep.getDirection() == UsbConstants.USB_DIR_IN) {
        if (m_usb_ep_in == null) {
          m_ep_in_addr = ep.getAddress();
          m_usb_ep_in = ep;
        }
      }
      else {
        if (m_usb_ep_out == null) {
          m_ep_out_addr = ep.getAddress();
          m_usb_ep_out = ep;
        }
      }
    }
    return 0;
  }

  private void acc_mode_switch() {
    int acc_ver = usb_acc_version_get(m_usb_dev_conn);
    usb_acc_strings_send();
    m_usb_dev_conn.controlTransfer(UsbConstants.USB_DIR_OUT | UsbConstants.USB_TYPE_VENDOR, OAP_START, 0, 0, null, 0, 10000);
  }

  private void usb_connect(UsbDevice device) {
    if (usb_open(device) < 0) {
      usb_disconnect();
      return;
    }
    int dev_vend_id = device.getVendorId();
    int dev_prod_id = device.getProductId();
    if (dev_vend_id == USB_VID_GOO && (dev_prod_id == USB_PID_OAP_NUL || dev_prod_id == USB_PID_OAP_ADB)) {
      int ret = acc_mode_connect();
      if (ret < 0) {
        usb_disconnect();
      }
      else {
        m_usb_connected = true;
        m_usb_device = device;
      }
      return;
    }
    acc_mode_switch();
    usb_disconnect();
  }

  int aa_cmd_send(int cmd_len, byte[] cmd_buf, int res_len, byte[] res_buf) {
    if (cmd_buf == null || cmd_len <= 0) {
      cmd_buf = new byte[256];
      cmd_len = 0;
    }
    if (res_buf == null || res_len <= 0) {
      res_buf = new byte[65535 * 16];
      res_len = res_buf.length;
    }

    int ret = native_aa_cmd(cmd_len, cmd_buf, res_len, res_buf);

    if (ret > 0) {
      Log.d(TAG, "ret is " + ret);
    }

    return ret;
  }

  public int jni_start() {
    byte[] cmd_buf = {121, -127, 2};
    cmd_buf[1] = (byte)m_ep_in_addr;
    cmd_buf[2] = (byte)m_ep_out_addr;
    int ret = aa_cmd_send(cmd_buf.length, cmd_buf, 0, null);

    return 0;
  }

  private void usb_attach_handler(UsbDevice device, boolean xyz) {
    if (!m_usb_connected) {
      usb_connect(device);
    }
    if (m_usb_connected) {
      jni_start();
    }
  }

  private void usb_detach_handler (UsbDevice device) {
    if (m_usb_device != null && device.equals (m_usb_device)) {
      usb_disconnect();
      android.os.Process.killProcess (android.os.Process.myPid ());
      return;
    }
  }
  public void usb_start() {
    IntentFilter filter = new IntentFilter();
    filter.addAction(UsbManager.ACTION_USB_DEVICE_ATTACHED);
    filter.addAction(UsbManager.ACTION_USB_DEVICE_DETACHED);
    filter.addAction(str_uas_perm);
    m_usb_receiver = new usb_receiver();

    Intent first_sticky_intent = m_context.registerReceiver(m_usb_receiver, filter);

    Map<String, UsbDevice> device_list = m_usb_mgr.getDeviceList();

    if (device_list != null) {
      for (UsbDevice device : device_list.values()) {
        usb_attach_handler(device, false);
      }
    }

  }

  public int transport_start() {
    Log.d(TAG, "in transport start");

    if (m_usb_connected) {
      Log.d(TAG, "Already m_usb_connected: " + m_usb_connected);
      return -1;
    }
    usb_start();

    return 0;
  }

  private class usb_receiver extends BroadcastReceiver {
    @Override
    public void onReceive (Context context, Intent intent) {
      UsbDevice device = intent.<UsbDevice>getParcelableExtra(UsbManager.EXTRA_DEVICE);
      if (device != null) {
        String action = intent.getAction();

        if (action.equals(UsbManager.ACTION_USB_DEVICE_DETACHED)) {
          usb_detach_handler(device);
        }
        else if (action.equals(UsbManager.ACTION_USB_DEVICE_ATTACHED)) {
          usb_attach_handler(device, false);
        }
      } 
    }
  }
}
