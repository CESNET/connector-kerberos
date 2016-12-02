#include <krb5.h>

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

char *krbconn_error(krbconn_context_t *ctx, long code);
long krbconn_renew(krbconn_context_t *ctx, krbconn_config_t *config);
long krbconn_init(krbconn_context_t *ctx, krbconn_config_t *config);
void krbconn_destroy(krbconn_context_t *ctx);
void krbconn_free_config(krbconn_config_t *config);
void krbconn_free_principal(krbconn_principal_t *principal);

long krbconn_get(krbconn_context_t *ctx, char *princ_name, krbconn_principal_t *result);
long krbconn_create(krbconn_context_t *ctx, krbconn_principal_t *info, char *pass);
long krbconn_delete(krbconn_context_t *ctx, char *name);
long krbconn_list(krbconn_context_t *ctx, char *search, char ***list, int *count);
void krbconn_free_list(krbconn_context_t *ctx, char **list, int count);
#endif
