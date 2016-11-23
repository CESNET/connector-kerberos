JAVA_HOME=$(shell for p in /usr/lib/jvm/java /usr/lib/jvm/default-java; do \
	if test -d $${p}; then \
		break; \
	fi; \
done; \
echo $${p}; \
)
LIB_OBJS=java_access.o kerberos.o

CC=gcc
CPPFLAGS:=-I. -I${JAVA_HOME}/include -I${JAVA_HOME}/include/linux -D_GNU_SOURCE $(CPPFLAGS)
CFLAGS:=-fPIC -W -Wall -g -O0 -std=c99 $(CFLAGS)
LIBS:=-lkrb5 -lkadm5clnt_mit $(LIBS)

all: libkerberos-connector.so krbconn_test

clean:
	rm -fv *.o *.so krbconn_test

libkerberos-connector.so: $(LIB_OBJS)
	$(CC) $(CFLAGS) $+ -o $@ -shared -Wl,-soname,libkerberos-connector.so $(LIBS)

krbconn_test: $(LIB_OBJS) krbconn_test.o
	$(CC) $(CFLAGS) $+ -o $@ $(LIBS)

.c.o: %.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $<

.PHONY: all clean
