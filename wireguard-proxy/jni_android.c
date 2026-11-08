#include <jni.h>
#include <stdlib.h>
#include "_cgo_export.h"

/* app.morphe.extension.music.patches.WireGuardPatch */

JNIEXPORT jint JNICALL
Java_app_morphe_extension_music_patches_WireGuardPatch_nativeStart(JNIEnv *env, jclass clazz, jstring config, jint port) {
    if (config == NULL) return -1;
    const char *c = (*env)->GetStringUTFChars(env, config, NULL);
    if (c == NULL) return -1;
    int result = wgStart((char *) c, (int) port);
    (*env)->ReleaseStringUTFChars(env, config, c);
    return (jint) result;
}

JNIEXPORT void JNICALL
Java_app_morphe_extension_music_patches_WireGuardPatch_nativeStop(JNIEnv *env, jclass clazz) {
    wgStop();
}

JNIEXPORT jstring JNICALL
Java_app_morphe_extension_music_patches_WireGuardPatch_nativeLastError(JNIEnv *env, jclass clazz) {
    char *e = wgLastError();
    jstring s = (*env)->NewStringUTF(env, e != NULL ? e : "");
    free(e);
    return s;
}
