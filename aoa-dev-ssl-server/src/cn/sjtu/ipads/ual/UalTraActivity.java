package cn.sjtu.ipads.ual;

import java.io.IOException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.ByteBuffer;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import android.content.Context;
import android.os.Handler;
import android.os.Handler.Callback;
import android.os.Message;
import android.os.Handler.Callback;

import android.hardware.usb.UsbAccessory;
import android.hardware.usb.UsbManager;

public class UalTraActivity extends Activity implements Callback, Runnable {

  public static final String TAG = "UalTraActivity";
  private Handler mDeviceHandler;
  
  private UsbManager mUSBManager;
  UsbAccessory mAccessory;
  Connection mConnection;

  private static final boolean gLogPackets = true;

  static final byte CHAN_CTR = 0;
  static final byte CHAN_VID = 1;
  static final byte CHAN_TOU = 2;
  static final byte CHAN_SEN = 3;
  
  static final int TYPE_VER_REQ = 1;
  static final int TYPE_SSL_HS_REQ_RSP = 3;
  static final int TYPE_SSL_AUTH_COMP = 4;
  static final int TYPE_HELLO_FROM_SERV = 5;
  static final int TYPE_HELLO_FROM_CLIENT = 6;

  static final byte FLAGS_ENCRYPT_FRAG = 0x08;
  static final byte FLAGS_ENCRYPT_ONLY_FRAG = 0x0b;

  private int hs_ctr = 0;
  static final int DEFBUF = 65536;

  static {
    System.loadLibrary("ual_jni");
  }
  
  private static native int nativeInit();
  private static native int nativeHandshakeDataEnqueue(int buf_len, byte[] buf);
  private static native int nativeHandshake(int hs_ctr);
  private static native int nativeHandshakeDataDequeue(byte[] buf);
  private static native int nativeEncryptData(int plain_len, byte[] plain_buf, byte[] cipher_buf);
  private static native int nativeDecryptData(int cipher_len, byte[] cipher_buf, byte[] plain_buf);

  @Override
  public void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    //setContentView(R.layout.main);
    
    Log.v(TAG, "onCreate");
    mDeviceHandler = new Handler(this);
    mUSBManager = (UsbManager) getSystemService(Context.USB_SERVICE);
    connectToAccessory();
  }

  @Override
  public void onDestroy() {
    closeAccessory();
    super.onDestroy();
  }

  public void connectToAccessory() {
    // bail out if we're already connected
    if (mConnection != null)
      return;

    Log.v(TAG, "connectToAccessory");
    // assume only one accessory (currently safe assumption)
    UsbAccessory[] accessories = mUSBManager.getAccessoryList();
    UsbAccessory accessory = (accessories == null ? null
        : accessories[0]);
    if (accessory != null) {
      if (mUSBManager.hasPermission(accessory)) {
        openAccessory(accessory);
      } else {
        Log.v(TAG, "no permission for accessory"); 
      }
    } else {
      Log.d(TAG, "mAccessory is null");
    }
  }

  private void openAccessory(UsbAccessory accessory) {
    Log.v(TAG, "openAccessory");
    mConnection = new UsbConnection(this, mUSBManager, accessory);
	if (mConnection == null) {
      Log.d(TAG, "mConnection is null");
	  finish();
	}
    performPostConnectionTasks();
  }

  private void performPostConnectionTasks() {
    Thread thread = new Thread(null, this, "UAL");
    thread.start();
  }

  public void closeAccessory() {
    try {
      if (mConnection != null) 
		mConnection.close();
    } catch (IOException e) {
    } finally {
      mConnection = null;
    }
  }

  public void run() {
    int ret = 0;
    byte[] buffer = new byte[DEFBUF];
    int bufferUsed = 0;

    while (ret >= 0) {
      try {
        ret = mConnection.getInputStream().read(buffer, bufferUsed,
            buffer.length - bufferUsed);
        bufferUsed += ret;
        int remainder = process(buffer, bufferUsed);
        if (remainder > 0) {
          System.arraycopy(buffer, remainder, buffer, 0, bufferUsed
              - remainder);
          bufferUsed = remainder;
        } else {
          bufferUsed = 0;
        }
      } catch (IOException e) {
        break;
      }
    }
    Log.v(TAG, "Exit thread.run()");
  }

  public int process(byte[] buffer, int bufferUsed) {
    if (gLogPackets) {
      Log.i(TAG,
          "read " + bufferUsed + " bytes: "
          + Utilities.dumpBytes(buffer, bufferUsed));
    }
    ByteArrayInputStream inputStream = new ByteArrayInputStream(buffer, 0,
        bufferUsed);
    ProtocolHandler ph = new ProtocolHandler(mDeviceHandler, inputStream);
    ph.process();
    return inputStream.available();
  }
  
  public boolean handleMessage(Message msg) {
    if (msg.getTarget() == mDeviceHandler) {
      return handleAccessoryMethod(msg);
    }
    return false;
  }

  private boolean handleAccessoryMethod(Message msg) {
    int chan = msg.what;
    int flags = msg.arg1;
    int length = msg.arg2;
    byte[] data = (byte[])msg.obj;

    switch (chan) {
      case CHAN_CTR:
        handleControlChannel(flags, length, data);
        return true;
    }
    return false;
  }

  private void encSendNamedBuffer(String name, byte[] buffer, int channel, int flags) {
    if (gLogPackets) Log.v(TAG, "Send " + name + " ("  + buffer.length + ")");
    byte[] cipherData = new byte[DEFBUF - 4];
    byte[] replyBuffer = new byte[DEFBUF];
    if (gLogPackets) {
      Log.i(TAG, "encrypting plainData (" + buffer.length + 
          "): " + Utilities.dumpBytes(buffer, buffer.length));
    }
    int cipherLength = nativeEncryptData(buffer.length, 
        buffer, cipherData);
    replyBuffer[0] = (byte)channel;
    replyBuffer[1] = (byte)flags;
    replyBuffer[2] = (byte)((cipherLength) / 256);
    replyBuffer[3] = (byte)((cipherLength) % 256);
    System.arraycopy(cipherData, 0, replyBuffer, 4, cipherLength);
    int ret = sendBuffer(cipherLength + 4, replyBuffer);
    if (ret != 0) {
      Log.v(TAG, "Send " + name + " failed");
    }
  }
  
  private void handleControlChannel(int flags, int length, byte[] data) {
    int type = 0;
    if (gLogPackets) {
      Log.i(TAG, "data length is: " + length);
    }
    if (flags >=  FLAGS_ENCRYPT_FRAG) {
      byte[] plainData = new byte[DEFBUF];
      int plainLength = nativeDecryptData(length, data, plainData);
      if (gLogPackets) {
        Log.i(TAG, "plainData (" + plainLength + 
            "): " + Utilities.dumpBytes(plainData, plainLength));
      }
      type = ((int) plainData[1] & 0xff) + ((int) plainData[0] & 0xff) * 256;
      if (gLogPackets) Log.v(TAG, "Received control type is " + type);
      switch (type) {
        case TYPE_HELLO_FROM_CLIENT:
          Log.v(TAG, "Get AOA Accessory Hello From OpenSSL Client");
        default:
          break;
      }
    } else {
      type = data[1] | (data[0] << 8);
      switch (type) {
        case TYPE_VER_REQ:
          if (data[2] == 0 && data[3] == 1 && data[4] == 0 && data[5] == 1) {
            byte buffer[] = { 0, 3, 0, 8, 0, 2, 0, 1, 0, 3, 0, 0 };
            if (gLogPackets) Log.v(TAG, "Received the first packet from headunit!");
            int ret = sendBuffer(12, buffer);
            if (ret != 0) {
              Log.v(TAG, "Send version response failed");
            }
          }
          break;
        case TYPE_SSL_HS_REQ_RSP:
          handleSslHandshake(length, data);
          break;
        case TYPE_SSL_AUTH_COMP:
          handleSslAuthComplete(length, data);
          break;
        default:
          break;
      }
    }
  }
 
  private void handleSslAuthComplete(int length, byte[] data) {
    if (gLogPackets) {
      Log.i(TAG, "SSL Auth Complete: "
          + Utilities.dumpBytes(data, length));
    }
    byte endata[] = { 0, 4, 0, TYPE_HELLO_FROM_SERV, 0, 1 };
    Log.v(TAG, "Send AOA Device Hello From OpenSSL Server");
    encSendNamedBuffer("First encrypted data from server", data, CHAN_CTR, FLAGS_ENCRYPT_ONLY_FRAG);
  }

  private void handleSslHandshake(int length, byte[] data) {
    if (hs_ctr == 0) {
      nativeInit();
      hs_ctr++;
    }
    if (hs_ctr < 3) {
      int replyLength = 0;
      byte[] replyData = new byte[DEFBUF - 6];
      byte[] replyBuffer = new byte[DEFBUF];
      nativeHandshakeDataEnqueue(length, data);
      nativeHandshake(hs_ctr);
      replyLength = nativeHandshakeDataDequeue(replyData);
      replyBuffer[0] = 0;
      replyBuffer[1] = 3;
      replyBuffer[2] = (byte)((replyLength + 2) / 256);
      replyBuffer[3] = (byte)((replyLength + 2) % 256);
      replyBuffer[4] = 0;
      replyBuffer[5] = 3;
      System.arraycopy(replyData, 0, replyBuffer, 6, replyLength);
      
      int ret = sendBuffer(replyLength + 6, replyBuffer);
      if (ret != 0) {
        Log.v(TAG, "handleSslHandshake failed");
      }
      hs_ctr++;
    }
  }

  private int sendBuffer(int bufferLength, byte[] buffer) {
    if (buffer == null || buffer.length < bufferLength) {
      Log.i(TAG, "allocating new command buffer of length "
          + bufferLength);
      buffer = new byte[bufferLength];
    }

    if (mConnection != null) {
      try {
        if (gLogPackets) {
          Log.i(TAG, "send encrypted data (" + bufferLength + ") :"
              + Utilities.dumpBytes(buffer, bufferLength));
        }
        mConnection.getOutputStream().write(buffer, 0, bufferLength);
      } catch (IOException e) {
        Log.e(TAG, "accessory write failed", e);
        return -1;
      }
    }
    return 0;
  }
  
  private static class ProtocolHandler {
    InputStream mInputStream;
    Handler mHandler;

    public ProtocolHandler(Handler handler, InputStream inputStream) {
      mHandler = handler;
      mInputStream = inputStream;
    }

    int readByte() throws IOException {
      int retVal = mInputStream.read();
      if (retVal == -1) {
        throw new RuntimeException("End of stream reached.");
      }
      return retVal;
    }

    int readInt16() throws IOException {
      int high = readByte();
      int low = readByte();
      if (gLogPackets) {
        Log.i(TAG, "readInt16 low=" + low + " high=" + high);
      }
      return low | (high << 8);
    }

    byte[] readBuffer(int bufferSize) throws IOException {
      byte readBuffer[] = new byte[bufferSize];
      int index = 0;
      int bytesToRead = bufferSize;
      while (bytesToRead > 0) {
        int amountRead = mInputStream.read(readBuffer, index,
            bytesToRead);
        if (amountRead == -1) {
          throw new RuntimeException("End of stream reached.");
        }
        bytesToRead -= amountRead;
        index += amountRead;
      }
      return readBuffer;
    }

    public void process() {
      mInputStream.mark(0);
      try {
        while (mInputStream.available() > 0) {
          if (gLogPackets)
            Log.i(TAG, "about to read opcode");
          int chan = readByte();
          int flags = readByte();
          int len = readInt16();
          if (gLogPackets)
            Log.i(TAG, "chan (" + chan + ") flags (" 
                + flags + ") len (" + len + ")");
          byte[] data = readBuffer(len);
          if (gLogPackets) {
            Log.i(TAG,
                "data: "
                + Utilities.dumpBytes(data,
                  data.length));
          }
          processReply(chan, flags, len, data);
          mInputStream.mark(0);
        }
        mInputStream.reset();
      } catch (IOException e) {
        Log.i(TAG, "ProtocolHandler error " + e.toString());
      }
    }

    private void processReply(int chan, int flags, int length, byte[] data) {
      Message msg = mHandler.obtainMessage(chan, flags, length, data);
      mHandler.sendMessage(msg);
    }
  }
}

