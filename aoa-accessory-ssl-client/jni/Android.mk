LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := uas_jni

LOCAL_CFLAGS := -fvisibility=hidden

LOCAL_SRC_FILES :=  uas_jni.c uas_usb.c uas_aap.c uas_ssl.c uas_uti.c

#LOCAL_LIBS := $(LOCAL_PATH)/libs/
#LOCAL_LDLIBS := -llog -lssl -lcrypto -lusbnok
#LOCAL_STATIC_LIBRARIES := libcrypto libssl libusbnok
LOCAL_LDLIBS := -llog -l/home/ytliu/disk/projects/android/auto/UsbAccServer/jni/libs/libssl.a -l/home/ytliu/disk/projects/android/auto/UsbAccServer/jni/libs/libcrypto.a -l/home/ytliu/disk/projects/android/auto/UsbAccServer/jni/libs/libusbnok.a
#LOCAL_LDLIBS := -llog -ljni/libs/libssl.a -ljni/libs/libcrypto.a -ljni/libs/libusbnok.a

include $(BUILD_SHARED_LIBRARY)
