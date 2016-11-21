#ifndef JAVA_ACCESS_H
#define JAVA_ACCESS_H

#include "kerberos.h"

char* jstring_getter(JNIEnv *, jobject, const char*);
char* jguardedstring_getter(JNIEnv *, jobject, const char*, jclass);
krbconn_context_t* getContext(JNIEnv*, jobject);

#endif
