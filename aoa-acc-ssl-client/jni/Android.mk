LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := uas_jni
LOCAL_SRC_FILES :=  uas_jni.c uas_usb.c uas_aap.c uas_ssl.c uas_uti.c

LOCAL_LDLIBS := -llog $(LOCAL_PATH)/libs/libssl.a $(LOCAL_PATH)/libs/libcrypto.a $(LOCAL_PATH)/libs/libusbnok.a

include $(BUILD_SHARED_LIBRARY)
