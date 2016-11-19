#include "cz_zcu_KerberosConnector.h"

char* jstring_getter(jobject obj, const char* name) {
	jclass cls = (*env)->GetObjectClass(env, obj);
	jmethodID mid = (*env)->GetMethodID(env, cls, name, "()Ljava/lang/String;");
	if (mid == 0) {
		return NULL;
	}

	jstring str = (*env)->CallObjectMethod(env, cls, mid);
	const char* temp = (*env)->GetStringUTFChars(env, str, 0);
	char* out = strdup(temp);
	(*env)->ReleaseStringUTFChars(env, str, temp);

	return out;
}

char* jguardedstring_getter(jobject obj, const char* name, jclass accessor) {
	jclass cls = (*env)->GetObjectClass(env, obj);
	jmethodID mid = (*env)->GetMethodID(env, cls, name, "()Lorg/identityconnectors/common/security/GuardedString;");
	if (mid == 0) {
		return NULL;
	}

	jobject guarded = (*env)->CallObjectMethod(env, cls, mid);
	mid = (*env)->GetStaticMethodID(env, accessor, "getString",
	                                "(Lorg/identityconnectors/common/security/GuardedString;)Ljava/lang/String;")

	jstring str = (*env)->CallStaticObjectMethod(env, accessor, mid, guarded);
	const char* temp = (*env)->GetStringUTFChars(env, str, 0);
	char* out = strdup(temp);
	(*env)->ReleaseStringUTFChars(env, str, temp);

	return out;
}