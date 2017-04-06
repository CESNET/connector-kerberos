#include <string.h>

#include "cz_zcu_KerberosConnector.h"
#include "java_access.h"

char* jstring_getter(JNIEnv * env, jobject obj, const char* name) {
	jclass cls = (*env)->GetObjectClass(env, obj);
	jmethodID mid = (*env)->GetMethodID(env, cls, name, "()Ljava/lang/String;");

	(*env)->DeleteLocalRef(env, cls);
	if (mid == NULL) {
		return NULL;
	}

	jstring str = (*env)->CallObjectMethod(env, obj, mid);
	if (str == 0) {
		return NULL;
	}
	const char* temp = (*env)->GetStringUTFChars(env, str, 0);
	char* out = strdup(temp);
	(*env)->ReleaseStringUTFChars(env, str, temp);
	(*env)->DeleteLocalRef(env, str);

	return out;
}

char* jguardedstring_getter(JNIEnv * env, jobject obj, const char* name, jclass accessor) {
	static jmethodID gsMid = NULL;
	char* out;

	jclass cls = (*env)->GetObjectClass(env, obj);
	jmethodID mid = (*env)->GetMethodID(env, cls, name, "()Lorg/identityconnectors/common/security/GuardedString;");

	(*env)->DeleteLocalRef(env, cls);
	if (mid == 0) {
		return NULL;
	}

	jobject guarded = (*env)->CallObjectMethod(env, obj, mid);

	if (gsMid == NULL) {
		gsMid = (*env)->GetStaticMethodID(env, accessor, "getString",
		                                  "(Lorg/identityconnectors/common/security/GuardedString;)Ljava/lang/String;");
	}

	jstring str = (*env)->CallStaticObjectMethod(env, accessor, gsMid, guarded);

	(*env)->DeleteLocalRef(env, guarded);
	(*env)->DeleteLocalRef(env, accessor);
	if (str == NULL) {
		out = NULL;
		goto out;
	}

	const char* temp = (*env)->GetStringUTFChars(env, str, 0);
	out = strdup(temp);
	(*env)->ReleaseStringUTFChars(env, str, temp);

out:
	(*env)->DeleteLocalRef(env, str);
	return out;
}

krbconn_context_t* getContext(JNIEnv* env, jobject this) {
	static jfieldID fid = NULL;
	if (fid == NULL) {
		jclass cls = (*env)->GetObjectClass(env, this);
		fid = (*env)->GetFieldID(env, cls, "contextPointer", "J");
		(*env)->DeleteLocalRef(env, cls);
	}

	krbconn_context_t* ctx = (krbconn_context_t*)(*env)->GetLongField(env, this, fid);
	return ctx;
}

void add_princ_to_array(JNIEnv* env, jobjectArray array, int pos, krbconn_principal_t princ, jclass clazz) {
	static jmethodID mid = NULL;
	if (mid == NULL) {
		mid = (*env)->GetMethodID(env, clazz, "<init>", "(Ljava/lang/String;JJJLjava/lang/String;JILjava/lang/String;)V");
	}

	jstring name = (*env)->NewStringUTF(env, princ.name);
	jstring modifyPrincipal = (*env)->NewStringUTF(env, princ.mod_name);
	jstring policy = (*env)->NewStringUTF(env, princ.policy);

	jobject jPrinc = (*env)->NewObject(env, clazz, mid, name, princ.princ_expire, princ.pwd_expire, princ.pwd_change,
	                                   modifyPrincipal, princ.mod_date, princ.attributes, policy);

	(*env)->DeleteLocalRef(env, name);
	(*env)->DeleteLocalRef(env, modifyPrincipal);
	(*env)->DeleteLocalRef(env, policy);

	(*env)->SetObjectArrayElement(env, array, pos, jPrinc);

	(*env)->DeleteLocalRef(env, jPrinc);
}

jint throwGenericException(JNIEnv* env, const char *exception, const char* message) {
	jclass exClass;

	exClass = (*env)->FindClass(env, exception);
	if (exClass)
		return (*env)->ThrowNew(env, exClass, message);

	exClass = (*env)->FindClass(env, "java/lang/NoClassDefFoundError");
	if (exClass)
		return (*env)->ThrowNew(env, exClass, exception);

	return 0;
}
