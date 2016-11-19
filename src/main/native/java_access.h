#ifndef JAVA_ACCESS_H
#define JAVA_ACCESS_H

char* jstring_getter(jobject, const char*);
char* jguardedstring_getter(jobject, const char*, jclass);

#endif
