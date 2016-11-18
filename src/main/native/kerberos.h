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
	time_t princ_expire;
	time_t pwd_expire;
	time_t pwd_change;

	char *mod_name;
	time_t mod_date;

	int attributes;
	char *policy;
} krbconn_principal_t;

char *krbconn_error(krbconn_context_t *ctx, krb5_error_code code);
krb5_error_code krbconn_init(krbconn_context_t *ctx, krbconn_config_t *config);
void krbconn_destroy(krbconn_context_t *ctx);
void krbconn_free_config(krbconn_config_t *config);
void krbconn_free_principal(krbconn_principal_t *principal);

krb5_error_code krbconn_get(krbconn_context_t *ctx, char *princ_name, krbconn_principal_t *result);
#endif
