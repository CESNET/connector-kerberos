JAVA_HOME=$(shell for p in /usr/lib/jvm/java /usr/lib/jvm/default-java; do \
	if test -d $${p}; then \
		break; \
	fi; \
done; \
echo $${p}; \
)
LIB_OBJS=java_access.o kerberos.o
KRB5_LIBS=-lkrb5 -lkadm5clnt_mit
EXAMPLES=krbconn_test parse_test fake_krbconn_test fake_parse_test

CC=gcc
CPPFLAGS:=-I. -I${JAVA_HOME}/include -I${JAVA_HOME}/include/linux -D_GNU_SOURCE $(CPPFLAGS)
CFLAGS:=-fPIC -W -Wall -g -O0 -std=c99 $(CFLAGS)

all: libkerberos-connector.so libkerberos-fake-connector.so $(EXAMPLES)

clean:
	rm -fv *.o *.so $(EXAMPLES)

libkerberos-connector.so: $(LIB_OBJS)
	$(CC) $(CFLAGS) $+ -o $@ -shared -Wl,-soname,libkerberos-connector.so $(KRB5_LIBS) $(LIBS)

libkerberos-fake-connector.so: $(LIB_OBJS) kadm5_fake.o
	$(CC) $(CFLAGS) $+ -o $@ -shared -Wl,-soname,libkerberos-connector.so $(LIBS)

krbconn_test: $(LIB_OBJS) krbconn_test.o
	$(CC) $(CFLAGS) $+ -o $@ $(KRB5_LIBS) $(LIBS)

parse_test: parse_test.o
	$(CC) $(CFLAGS) $+ -o $@ $(KRB5_LIBS) $(LIBS)

fake_krbconn_test: $(LIB_OBJS) kadm5_fake.o krbconn_test.o
	$(CC) $(CFLAGS) $+ -o $@ $(LIBS)

fake_parse_test: kadm5_fake.o parse_test.o
	$(CC) $(CFLAGS) $+ -o $@ $(LIBS)

.c.o: %.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $<

.PHONY: all clean
