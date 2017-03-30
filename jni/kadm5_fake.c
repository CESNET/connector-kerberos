/* fake kamd5 library with read-only static data */

#include <stdio.h>
#include <string.h>

#include <kadm5/admin.h>


#define REALM "EXAMPLE.COM"
#define REALM_LENGTH 11
#define ADMIN_NAME "admin"
#define ADMIN_NAME_LEN 5
#define ADMIN_PRINCIPAL ADMIN_NAME "@" REALM
#define ADMIN_PASSWORD "password"
#define USER_NAME "user"
#define USER_NAME_LEN 4

#define MAGIC_DATA 0x20010718
#define MAGIC_PRINC 0x20010719


typedef enum {
	NO_ERROR = 0,
	ERROR_MISSING_KEY,
	ERROR_BAD_DATA,
	ERROR_LOGIN_FAILED,
	ERROR_UNKNOWN_PRINCIPAL,
	ERROR_NUMBER_EXCEEDED,
	ERROR_ALREADY_EXISTS,
	ERROR_BAD_REALM,
	LAST_ERROR_CODE,
} _krb5_error_code;

typedef struct _krb5_context {
} _krb5_context;

typedef struct {
	char *realm;
	krb5_context ctx;
} _kadm5_handle;


static const char *errors[] = {
	"no error",
	"password or key required",
	"invalid data",
	"login failed",
	"unknown principal",
	"too much principals",
	"principal already exists",
	"bad realm",
	"bad error code",
};
#define LAST_ERROR ((sizeof(errors) / sizeof (char *)) - 1)

static krb5_data fake_names[] = {
	{magic: MAGIC_DATA, length: ADMIN_NAME_LEN, data: ADMIN_NAME, },
	{magic: MAGIC_DATA, length: USER_NAME_LEN, data: "user", },
	{magic: MAGIC_DATA, length: 5, data: "user2", },
	{magic: MAGIC_DATA, length: 6, data: "user3", },
};

#define REALM_DATA { \
		magic: MAGIC_DATA, \
		length: REALM_LENGTH, \
		data: REALM, \
}

static krb5_principal_data fake_principals[] = {
	{ magic: MAGIC_PRINC, realm: REALM_DATA, data: fake_names + 0, length: 1, },
	{ magic: MAGIC_PRINC, realm: REALM_DATA, data: fake_names + 1, length: 1, },
	{ magic: MAGIC_PRINC, realm: REALM_DATA, data: fake_names + 2, length: 1, },
	{ magic: MAGIC_PRINC, realm: REALM_DATA, data: fake_names + 3, length: 1, },
};

kadm5_principal_ent_rec fake_db[] = {
	{ principal: fake_principals + 0, attributes: 128, mod_name: fake_principals + 0, policy: "default", },
	{ principal: fake_principals + 1, attributes: 128, mod_name: fake_principals + 0, policy: "default", },
	{ principal: fake_principals + 2, attributes: 128, mod_name: fake_principals + 0, policy: "default", },
	{ principal: fake_principals + 3, attributes: 128, mod_name: fake_principals + 0, policy: "default", },
};
#define FAKE_N (sizeof(fake_db) / sizeof(kadm5_principal_ent_rec))


static int principal_equals(krb5_const_principal a, krb5_const_principal b) {
	return
		(strcmp(a->realm.data, b->realm.data) == 0) &&
		(strcmp(a->data[0].data, b->data[0].data) == 0);
}


static int fake_search(krb5_context ctx __attribute ((unused)), krb5_const_principal principal) {
	size_t i;

	for (i = 0; i < FAKE_N; i++) {
		if (principal_equals(principal, fake_db[i].principal)) break;
	}
	if (i >= FAKE_N) return -1;
	return i;
}


static int check_data(const krb5_data *data) {
	if (!data || data->magic != MAGIC_DATA) return ERROR_BAD_DATA;
	return 0;
}


static int check_principal(krb5_const_principal principal) {
	if (principal->magic != MAGIC_PRINC) return ERROR_BAD_DATA;
	if (principal->length != 1 || (check_data(principal->data) != 0)) return ERROR_BAD_DATA;
	if (check_data(&principal->realm) != 0) return ERROR_BAD_DATA;

	return 0;
}


/*
 * KRB5 API fake functions
 */

void krb5_free_context(krb5_context ctx) {
	free(ctx);
}


krb5_error_code krb5_get_default_realm(krb5_context ctx __attribute ((unused)), char **realm) {
	*realm = strdup(REALM);
	return 0;
}


void krb5_free_default_realm(krb5_context ctx __attribute ((unused)), char *realm) {
	realm[0] = '\0'; // to test memory
	free(realm);
}


krb5_error_code krb5_parse_name(krb5_context ctx __attribute ((unused)), const char *name, krb5_principal *principal_out) {
	const char *p, *realm = NULL;
	krb5_principal principal = calloc(sizeof(*principal), 1);
	char *princ_name;
	size_t i = 0, j = 0;
	int len;
	krb5_data *data = calloc(sizeof(*data), 1);

	len = strlen(name);
	princ_name = malloc(len + 1);
	p = name;
	while ((p - name) < len) {
		i = strcspn(p, "\\@");
		if (i) memcpy(princ_name + j, p, i);
		j += i;
		p += i;
		switch (p[0]) {
			case '\\':
				p++;
				princ_name[j++] = p[0];
				p++;
				break;
			case '@':
				p++;
				realm = p;
				break;
			default:
				break;
		}
		if (realm) break;
	}
	princ_name[j] = '\0';
	realm = realm ? : REALM;

	data[0].magic = MAGIC_DATA;
	data[0].data = princ_name;
	data[0].length = j;
	principal->magic = MAGIC_PRINC;
	principal->realm.magic = MAGIC_DATA;
	principal->realm.data = strdup(realm);
	principal->realm.length = strlen(realm);
	principal->data = data;
	principal->length = 1;
	*principal_out = principal;

	return 0;
}


void krb5_free_principal(krb5_context ctx __attribute ((unused)), krb5_principal principal) {
	int i;

	if (principal->magic != MAGIC_PRINC) {
		fprintf(stderr, "%s: %s\n", __func__, errors[ERROR_BAD_DATA]);
		return;
	}
	free(principal->realm.data);

	for (i = 0; i < principal->length; i++) free(principal->data[i].data);
	free(principal->data);
	free(principal);
}


krb5_error_code krb5_unparse_name(krb5_context ctx __attribute ((unused)), krb5_const_principal principal, register char **name) {
	if (check_principal(principal) != 0) return ERROR_BAD_DATA;
	asprintf(name, "%s@%s", principal->data[0].data, principal->realm.data);

	return 0;
}


void krb5_free_unparsed_name(krb5_context ctx __attribute ((unused)), char *val) {
	free(val);
}


const char *krb5_get_error_message(krb5_context ctx __attribute ((unused)), krb5_error_code code) {
	if (code < 0 || code > LAST_ERROR_CODE) code = LAST_ERROR;

	return strdup(errors[code]);
}


void krb5_free_error_message(krb5_context ctx __attribute ((unused)), const char *msg) {
	free((char *)msg);
}


/*
 * KADM5 API fake functions
 */

/** call krb5_free_context() to free */
krb5_error_code kadm5_init_krb5_context(krb5_context *pctx) {
	krb5_context ctx = calloc(sizeof(_krb5_context), 1);

	*pctx = ctx;

	return 0;
}


kadm5_ret_t kadm5_init_with_password(
	krb5_context ctx,
	char *client_name,
	char *pass,
	char *service_name __attribute ((unused)),
	kadm5_config_params *params,
	krb5_ui_4 struct_version __attribute ((unused)),
	krb5_ui_4 api_version __attribute ((unused)),
	char **db_args __attribute ((unused)),
	void **server_handle)
{
	_kadm5_handle *handle;

	if ((params->mask & KADM5_CONFIG_REALM) == 0) return ERROR_BAD_REALM;
	if (strcmp(ADMIN_PRINCIPAL, client_name) != 0 && strcmp(ADMIN_NAME, client_name) != 0) return ERROR_LOGIN_FAILED;
	if (pass) {
		if (strcmp(ADMIN_PASSWORD, pass) != 0) return ERROR_LOGIN_FAILED;
	} else {
		return ERROR_MISSING_KEY;
	}

	handle = calloc(sizeof(*handle), 1);
	handle->ctx = ctx;
	handle->realm = strdup(params->realm);
	*server_handle = handle;

	return 0;
}


kadm5_ret_t kadm5_init_with_skey(
	krb5_context ctx,
	char *client_name,
	char *keytab __attribute ((unused)),
	char *service_name __attribute ((unused)),
	kadm5_config_params *params,
	krb5_ui_4 struct_version __attribute ((unused)),
	krb5_ui_4 api_version __attribute ((unused)),
	char **db_args __attribute ((unused)),
	void **server_handle)
{
	_kadm5_handle *handle;

	if ((params->mask & KADM5_CONFIG_REALM) == 0) return ERROR_BAD_REALM;
	if (strcmp(ADMIN_PRINCIPAL, client_name) != 0 && strcmp(ADMIN_NAME, client_name) != 0) return ERROR_LOGIN_FAILED;

	handle = calloc(sizeof(*handle), 1);
	handle->ctx = ctx;
	handle->realm = strdup(params->realm);
	*server_handle = handle;

	return 0;
}


kadm5_ret_t kadm5_destroy(void *server_handle) {
	_kadm5_handle *handle = server_handle;

	free(handle->realm);
	free(handle);

	return 0;
}


kadm5_ret_t kadm5_get_principal(
	void *server_handle,
	krb5_principal principal,
	kadm5_principal_ent_t ent,
	long mask __attribute ((unused)))
{
	int i;
	_kadm5_handle *handle = server_handle;
	_krb5_context *ctx = handle->ctx;

	if (check_principal(principal) != 0) return ERROR_BAD_DATA;

	i = fake_search(ctx, principal);
	if (i == -1) return ERROR_UNKNOWN_PRINCIPAL;
	*ent = fake_db[i];

	return 0;
}


kadm5_ret_t kadm5_free_principal_ent(
	void *server_handle __attribute__((unused)),
	kadm5_principal_ent_t ent __attribute__((unused)))
{
	return 0;
}


/* just checks, if principal exists */
kadm5_ret_t kadm5_create_principal(
	void *server_handle,
	kadm5_principal_ent_t ent,
	long mask __attribute__((unused)),
	char *pass __attribute__((unused)))
{
	int i;
	_kadm5_handle *handle = server_handle;
	_krb5_context *ctx = handle->ctx;

	if (check_principal(ent->principal) != 0) return ERROR_BAD_DATA;

	i = fake_search(ctx, ent->principal);
	if (i != -1) return ERROR_ALREADY_EXISTS;

	return 0;
}


/* just checks, if principal exists */
kadm5_ret_t kadm5_delete_principal(
	void *server_handle,
	krb5_principal principal)
{
	int i;
	_kadm5_handle *handle = server_handle;
	_krb5_context *ctx = handle->ctx;

	if (check_principal(principal) != 0) return ERROR_BAD_DATA;

	i = fake_search(ctx, principal);
	if (i == -1) return ERROR_UNKNOWN_PRINCIPAL;

	return 0;
}


/* just checks the principal existence */
kadm5_ret_t kadm5_modify_principal(
	void *server_handle,
	kadm5_principal_ent_t ent,
	long mask __attribute__((unused)))
{
	int i;
	_kadm5_handle *handle = server_handle;
	_krb5_context *ctx = handle->ctx;

	if (check_principal(ent->principal) != 0) return ERROR_BAD_DATA;

	i = fake_search(ctx, ent->principal);
	if (i == -1) return ERROR_UNKNOWN_PRINCIPAL;

	return 0;
}


/* just checks the principals existence */
kadm5_ret_t kadm5_rename_principal(
	void *server_handle,
	krb5_principal old,
	krb5_principal new)
{
	int i;
	_kadm5_handle *handle = server_handle;
	_krb5_context *ctx = handle->ctx;

	if (check_principal(old) != 0) return ERROR_BAD_DATA;
	if (check_principal(new) != 0) return ERROR_BAD_DATA;

	i = fake_search(ctx, old);
	if (i == -1) return ERROR_UNKNOWN_PRINCIPAL;

	i = fake_search(ctx, new);
	if (i != -1) return ERROR_ALREADY_EXISTS;

	return 0;
}


/**
 * Get available principals.
 *
 * Query expression is handled only using plain string compare.
 */
kadm5_ret_t kadm5_get_principals(
	void *server_handle,
	char *exp,
	char ***princs,
	int *count)
{
	int i, j;
	char *name;
	krb5_error_code err;
	_kadm5_handle *handle = server_handle;
	_krb5_context *ctx = handle->ctx;

	*princs = calloc(sizeof(char *), FAKE_N);
	for (i = 0, j = 0; i < (int)FAKE_N; i++) {
		err = krb5_unparse_name(ctx, fake_db[i].principal, &name);
		if (err) {
			for (i = i - 1; i >= 0; i--) free((*princs)[i]);
			free(*princs);
			return err;
		}
		if (!exp || (strcmp(exp, name) == 0)) {
			(*princs)[j++] = name;
		}
	}
	*count = j;

	return 0;
}


kadm5_ret_t kadm5_free_name_list(
	void *server_handle __attribute__((unused)),
	char **names,
	int count)
{
	int i;

	for (i = 0; i < count; i++) free(names[i]);
	free(names);

	return 0;
}


/* just checks the principals existence */
kadm5_ret_t kadm5_chpass_principal(
	void *server_handle,
	krb5_principal principal,
	char *pass __attribute__((unused)))
{
	int i;
	_kadm5_handle *handle = server_handle;
	_krb5_context *ctx = handle->ctx;

	if (check_principal(principal) != 0) return ERROR_BAD_DATA;

	i = fake_search(ctx, principal);
	if (i == -1) return ERROR_UNKNOWN_PRINCIPAL;

	return 0;
}
