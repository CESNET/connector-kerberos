#include <kadm5/admin.h>

#ifndef KERBEROS_CONNECTOR_H
#define KERBEROS_CONNECTOR_H

typedef struct {
	/* keytab or password needed */
	char *keytab;
	char *password;
	char *principal;
	char *realm;
} krbconn_config_t;

typedef struct {
	krb5_context krb;
	void *handle;
} krbconn_context_t;

typedef struct {
	char *name;
	char *mod_name;
} krbconn_principal_t;

#endif
