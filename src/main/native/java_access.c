#include <string.h>

#include "cz_zcu_KerberosConnector.h"
#include "java_access.h"

char* jstring_getter(JNIEnv * env, jobject obj, const char* name) {
	jclass cls = (*env)->GetObjectClass(env, obj);
	jmethodID mid = (*env)->GetMethodID(env, cls, name, "()Ljava/lang/String;");
	if (mid == 0) {
		return NULL;
	}

	jstring str = (*env)->CallObjectMethod(env, obj, mid);
	if (str == 0) {
		return NULL;
	}
	const char* temp = (*env)->GetStringUTFChars(env, str, 0);
	char* out = strdup(temp);
	(*env)->ReleaseStringUTFChars(env, str, temp);

	return out;
}

char* jguardedstring_getter(JNIEnv * env, jobject obj, const char* name, jclass accessor) {
	jclass cls = (*env)->GetObjectClass(env, obj);
	jmethodID mid = (*env)->GetMethodID(env, cls, name, "()Lorg/identityconnectors/common/security/GuardedString;");
	if (mid == 0) {
		return NULL;
	}

	jobject guarded = (*env)->CallObjectMethod(env, obj, mid);
	mid = (*env)->GetStaticMethodID(env, accessor, "getString",
	                                "(Lorg/identityconnectors/common/security/GuardedString;)Ljava/lang/String;");

	jstring str = (*env)->CallStaticObjectMethod(env, accessor, mid, guarded);
	if (str == NULL) {
		// If password is empty, the method returns NULL
		return NULL;
	}
	const char* temp = (*env)->GetStringUTFChars(env, str, 0);
	char* out = strdup(temp);
	(*env)->ReleaseStringUTFChars(env, str, temp);

	return out;
}

krbconn_context_t* getContext(JNIEnv* env, jobject this) {
	jclass cls = (*env)->GetObjectClass(env, this);
	jfieldID fid = (*env)->GetFieldID(env, cls, "contextPointer", "J");
	krbconn_context_t* ctx = (krbconn_context_t*)(*env)->GetLongField(env, this, fid);
	return ctx;
}

void add_princ_to_array(JNIEnv* env, jobjectArray array, krbconn_principal_t princ, jclass clazz) {
	jmethodID mid = (*env)->GetMethodID(env, clazz, "<init>", "(Ljava/lang/String;JJLjava/lang/String;JILjava/lang/String)V");

	jobject jPrinc = (*env)->NewObject(env, clazz, mid, ...);
}
