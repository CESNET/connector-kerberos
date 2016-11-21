#ifndef JAVA_ACCESS_H
#define JAVA_ACCESS_H

char* jstring_getter(JNIEnv *, jobject, const char*);
char* jguardedstring_getter(JNIEnv *, jobject, const char*, jclass);

#endif
