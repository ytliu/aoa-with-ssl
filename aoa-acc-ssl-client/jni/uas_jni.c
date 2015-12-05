#include <stdio.h>
#include <jni.h>
#include "uas_uti.h"
#include "uas_aap.h"

int jni_aa_cmd(int cmd_len, char *cmd_buf, int res_max, char *res_buf) {
    logd("cmd_len: %d cmd_buf %p res_max: %d res_buf: %p\n", cmd_len, cmd_buf, res_max, res_buf);
    int res_len = 0;
    int ret = 0;

    if (cmd_buf != NULL && cmd_len == 3 && cmd_buf[0] == 121) {
        byte ep_in_addr = cmd_buf[1];
        byte ep_out_addr = cmd_buf[2];
        ret = uas_aap_start(ep_in_addr, ep_out_addr);
    }
    if (cmd_buf != NULL && cmd_len >= 4) {
        printf("If encrypted command to send...\n");
    }

    return 0;
}

JNIEXPORT jint Java_cn_sjtu_ipads_uas_UasTransport_native_1aa_1cmd(JNIEnv *env, jobject thiz,
    jint cmd_len, jbyteArray cmd_buf, jint res_len, jbyteArray res_buf) {
    jbyte *aa_cmd_buf = NULL;
    jbyte *aa_res_buf = NULL;

    aa_cmd_buf = (*env)->GetByteArrayElements(env, cmd_buf, NULL);
    aa_res_buf = (*env)->GetByteArrayElements(env, res_buf, NULL);

    int len = jni_aa_cmd(cmd_len, aa_cmd_buf, res_len, aa_res_buf);

    if (cmd_buf != NULL) {
        (*env)->ReleaseByteArrayElements(env, cmd_buf, aa_cmd_buf, 0);
    }

    if (res_buf != NULL) {
        (*env)->ReleaseByteArrayElements(env, res_buf, aa_res_buf, 0);
    }

    return len;
}
