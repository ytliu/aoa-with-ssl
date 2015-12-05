
LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE:= ual_jni
LOCAL_SRC_FILES:= ual_jni.c ual_uti.c

LOCAL_LDLIBS := -llog $(LOCAL_PATH)/libs/libssl.a $(LOCAL_PATH)/libs/libcrypto.a

include $(BUILD_SHARED_LIBRARY)

