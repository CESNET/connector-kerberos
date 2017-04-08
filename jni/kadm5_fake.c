/*
 * Fake kamd5 library
 */

#ifdef FAKE_PTHREAD
#include <pthread.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fnmatch.h>
#include <time.h>

#include <kadm5/admin.h>


#define DEFAULT_FAKE_KADM5_DATA "target/test-classes/data.csv"
#define DEFAULT_REALM "EXAMPLE.COM"

#define FAKE_MAX_N 128
#define FAKE_COLUMNS 6

#define MAGIC_DATA 0x20010718
#define MAGIC_PRINC 0x20010719

/*
 * locking would be needed, when sharing the fake DB between threads
 */
#ifdef FAKE_PTHREAD
	#define LOCK(ctx) ((pthread_mutex_lock(&((ctx))->lock)))
	#define UNLOCK(ctx) ((pthread_mutex_unlock(&((ctx))->lock)))
#else
	#define LOCK(ctx)
	#define UNLOCK(ctx)
#endif


typedef struct _fake_kadm5_principal {
	char *name;
	char *password;
	char *policy;
	int attributes;

	char *modification_name;
	time_t modification;
	time_t pw_expiration;
	time_t pw_change;
	time_t expiration;

	time_t max_ticket_life;
	time_t max_renewable_life;
} _fake_kadm5_principal, *fake_kadm5_principal;

typedef struct _krb5_context {
#ifdef FAKE_PTHREAD
	pthread_mutex_t lock;
#endif
	_fake_kadm5_principal db[FAKE_MAX_N];
	size_t n;

	char *admin_name, *admin_password;
	char *realm;
	size_t rlen;
} _krb5_context;

typedef struct {
	char *realm;
	krb5_context ctx;
} _kadm5_handle;

typedef enum {
	NO_ERROR = 0,
	ERROR_OPEN_DATA_FILE,
	ERROR_PARSE_DATA_FILE,
	ERROR_MISSING_KEY,
	ERROR_BAD_DATA,
	ERROR_LOGIN_FAILED,
	ERROR_UNKNOWN_PRINCIPAL,
	ERROR_NUMBER_EXCEEDED,
	ERROR_ALREADY_EXISTS,
	ERROR_BAD_REALM,
	ERROR_MISSING_PRINCIPAL,
	ERROR_INVALID_INPUT,
	ERROR_INIT,
	LAST_ERROR_CODE,
} _krb5_error_code;

static const char *errors[] = {
	"no error",
	"can't open testing data file",
	"can't parse testing data file",
	"password or key required",
	"invalid data",
	"login failed",
	"unknown principal",
	"too much principals",
	"principal already exists",
	"bad realm",
	"missing principal",
	"wrong input parameters",
	"init failed",
	"bad error code",
};
#define LAST_ERROR ((sizeof(errors) / sizeof (char *)) - 1)



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


static int principal_is(krb5_const_principal principal, const char *realm, const char *name) {
	return
		(strcmp(principal->realm.data, realm) == 0) &&
		(strcmp(principal->data[0].data, name) == 0);
}


static void clone_record(fake_kadm5_principal record, const fake_kadm5_principal src) {
	record->name = strdup(src->name);
	record->password = src->password ? strdup(src->password) : NULL;
	record->policy = src->policy ? strdup(src->policy) : NULL;
	record->attributes = src->attributes;
	record->modification_name = src->modification_name ? strdup(src->modification_name) : NULL;
	record->modification = src->modification;
	record->pw_expiration = src->pw_expiration;
	record->expiration = src->expiration;
}


static void free_record(fake_kadm5_principal record) {
	free(record->name);
	free(record->password);
	free(record->policy);
	free(record->modification_name);
	memset(record, 0, sizeof(*record));
}


/*
 * Fill the fake record
 *
 * The record should be already valid or nullified.
 */
static int fill_record(krb5_context ctx, fake_kadm5_principal record, kadm5_principal_ent_t ent, long mask) {
	if (check_principal(ent->principal) != 0) return ERROR_BAD_DATA;
	if (strcmp(ent->principal->realm.data, ctx->realm) != 0) return ERROR_BAD_REALM;

	if ((mask & KADM5_PRINCIPAL) != 0) {
		free(record->name);
		record->name = strdup(ent->principal->data[0].data);
	}
	if ((mask & KADM5_POLICY) != 0) {
		free(record->policy);
		record->policy = ent->policy ? strdup(ent->policy) : NULL;
	}
	if ((mask & KADM5_POLICY_CLR) != 0) {
		free(record->policy);
		record->policy = NULL;
	}
	if ((mask & KADM5_PRINC_EXPIRE_TIME) != 0)
		record->expiration = ent->princ_expire_time;
	if ((mask & KADM5_PW_EXPIRATION) != 0)
		record->pw_expiration = ent->pw_expiration;
	if ((mask & KADM5_LAST_PWD_CHANGE) != 0)
		record->pw_change = ent->last_pwd_change;
	if ((mask & KADM5_ATTRIBUTES) != 0)
		record->attributes = ent->attributes;
	if ((mask & KADM5_MAX_LIFE) != 0)
		record->max_ticket_life = ent->max_life;
	if ((mask & KADM5_MAX_RLIFE) != 0)
		record->max_renewable_life = ent->max_renewable_life;
	free(record->modification_name);
	record->modification_name = strdup(ctx->admin_name);
	record->modification = time(NULL);

	return 0;
}


/**
 * Parse csv line into fake principal record
 */
static int str2db(char *line, fake_kadm5_principal record) {
	char *value;
	char *values[FAKE_COLUMNS];
	size_t i = 0;

	memset(values, 0, sizeof values);
	while (((value = strsep(&line, ",")) != NULL) && (i < FAKE_COLUMNS)) {
		values[i++] = value;
	}

	if (!values[0] || !values[0][0]) return ERROR_PARSE_DATA_FILE;

	memset(record, 0, sizeof(_fake_kadm5_principal));
	record->name = values[0];
	record->password = values[1];
	record->policy = values[2];
	record->attributes = values[3] ? atoi(values[3]) : 0;
	record->modification_name = values[4];
	record->modification = values[5] ? atol(values[5]) : 0;
	record->pw_expiration = 0;
	record->expiration = 0;
	clone_record(record, record);

	return 0;
}


static int fake_search(krb5_context ctx, krb5_const_principal principal) {
	size_t i;

	for (i = 0; i < ctx->n; i++) {
		if (principal_is(principal, ctx->realm, ctx->db[i].name)) break;
	}
	if (i >= ctx->n) return -1;

	return i;
}


/*
 * Free loaded fake database
 */
static void db_free(krb5_context ctx) {
	size_t i;

	LOCK(ctx);
	for (i = 0; i < ctx->n; i++) {
		free_record(&ctx->db[i]);
	}
	ctx->n = 0;
	UNLOCK(ctx);
}


/**
 * Load fake database
 */
static int db_load(krb5_context ctx, const char *path) {
	char buf[256];
	FILE *f;
	int code;

	if ((f = fopen(path, "rt")) == NULL) return ERROR_OPEN_DATA_FILE;
	// header
	if (fgets(buf, sizeof(buf), f) == NULL) {
		fclose(f);
		return ERROR_PARSE_DATA_FILE;
	}
	// data
	LOCK(ctx);
	while ((ctx->n < FAKE_MAX_N) && (fgets(buf, sizeof(buf), f) != NULL)) {
		if ((code = str2db(buf, &ctx->db[ctx->n])) != 0) {
			UNLOCK(ctx);
			db_free(ctx);
			fclose(f);
			return code;
		}
		ctx->n++;
	}
	UNLOCK(ctx);

	fclose(f);
	return 0;
}


/**
 * Generate Krb5 principal data from fake database
 */
static int db_get(krb5_context ctx, kadm5_principal_ent_t ent, krb5_const_principal principal) {
	krb5_error_code code;
	fake_kadm5_principal record;
	int i;

	if (check_principal(principal) != 0) return ERROR_BAD_DATA;

	LOCK(ctx);
	i = fake_search(ctx, principal);
	if (i == -1) {
		UNLOCK(ctx);
		return ERROR_UNKNOWN_PRINCIPAL;
	}
	record = &ctx->db[i];

	memset(ent, 0, sizeof(*ent));

	code = krb5_build_principal(ctx, &ent->principal, ctx->rlen, ctx->realm, ctx->db[i].name, NULL);
	if (code) {
		UNLOCK(ctx);
		return code;
	}

	ent->princ_expire_time = record->expiration;
	ent->pw_expiration = record->pw_expiration;
	if (record->modification_name) {
		size_t j;

		for (j = 0; j < ctx->n; j++) {
			if (strcmp(record->modification_name, ctx->db[j].name)) break;
		}
		if (j < ctx->n)
			krb5_build_principal(ctx, &ent->mod_name, ctx->rlen, ctx->realm, ctx->db[j].name, NULL);
	}
	ent->mod_date = record->modification;
	ent->attributes = record->attributes;
	ent->policy = record->policy ? strdup(record->policy) : NULL;

	ent->max_life = record->max_ticket_life;
	ent->max_renewable_life = record->max_renewable_life;

	UNLOCK(ctx);
	return 0;
}


/**
 * Put Krb5 principal data to the fake database
 */
static int db_put(krb5_context ctx, kadm5_principal_ent_t ent, long mask, const char *pass) {
	fake_kadm5_principal record;
	int code;
	size_t i;

	if (check_principal(ent->principal) != 0) return ERROR_BAD_DATA;
	if ((mask & KADM5_PRINCIPAL) == 0) return ERROR_MISSING_PRINCIPAL;
	mask |= (KADM5_PRINCIPAL | KADM5_POLICY | KADM5_ATTRIBUTES | KADM5_PW_EXPIRATION | KADM5_LAST_PWD_CHANGE | KADM5_PRINC_EXPIRE_TIME | KADM5_MAX_LIFE | KADM5_MAX_RLIFE);

	LOCK(ctx);
	i = fake_search(ctx, ent->principal);
	if (i != -1) {
		UNLOCK(ctx);
		return ERROR_ALREADY_EXISTS;
	}

	if (ctx->n >= FAKE_MAX_N) {
		UNLOCK(ctx);
		return ERROR_NUMBER_EXCEEDED;
	}
	record = &ctx->db[ctx->n];
	memset(record, 0, sizeof(*record));
	code = fill_record(ctx, record, ent, mask);
	if (code) {
		UNLOCK(ctx);
		return code;
	}
	record->password = pass ? strdup(pass) : NULL;
	ctx->n++;

	UNLOCK(ctx);
	return 0;
}


/**
 * Remove Krb5 principal data from the fake database
 */
static int db_remove(krb5_context ctx, krb5_principal principal) {
	size_t i, j;

	if (check_principal(principal) != 0) return ERROR_BAD_DATA;

	LOCK(ctx);
	i = fake_search(ctx, principal);
	if (i == -1) {
		UNLOCK(ctx);
		return ERROR_UNKNOWN_PRINCIPAL;
	}

	if (i >= FAKE_MAX_N) {
		UNLOCK(ctx);
		return ERROR_NUMBER_EXCEEDED;
	}

	free_record(&ctx->db[i]);
	for (j = i; j + 1 < ctx->n; j++) {
		ctx->db[j] = ctx->db[j+1];
	}
	ctx->n--;

	UNLOCK(ctx);
	return 0;
}


/**
 * Modify Krb5 principal data in the fake database
 */
static int db_modify(krb5_context ctx, kadm5_principal_ent_t ent, long mask) {
	fake_kadm5_principal record;
	size_t i;
	int code;

	if ((mask & KADM5_PRINCIPAL) != 0) return ERROR_INVALID_INPUT;
	if (check_principal(ent->principal) != 0) return ERROR_BAD_DATA;

	LOCK(ctx);
	i = fake_search(ctx, ent->principal);
	if (i == -1) {
		UNLOCK(ctx);
		return ERROR_UNKNOWN_PRINCIPAL;
	}

	record = &ctx->db[i];
	code = fill_record(ctx, record, ent, mask);

	UNLOCK(ctx);
	return code;
}


/*
 * =======================
 * KRB5 API fake functions
 * =======================
 */

void krb5_free_context(krb5_context ctx) {
	db_free(ctx);
#ifdef FAKE_PTHREAD
	pthread_mutex_destroy(&ctx->lock);
#endif
	free(ctx->admin_name);
	free(ctx->admin_password);
	free(ctx->realm);
	free(ctx);
}


krb5_error_code krb5_get_default_realm(krb5_context ctx, char **realm) {
	*realm = strdup(ctx->realm);
	return 0;
}


void krb5_free_default_realm(krb5_context ctx __attribute ((unused)), char *realm) {
	if (realm) realm[0] = '\0'; // to test memory
	free(realm);
}


krb5_error_code krb5_parse_name(krb5_context ctx, const char *name, krb5_principal *principal_out) {
	krb5_error_code code;
	const char *p, *realm = NULL;
	char *princ_name;
	size_t i = 0, j = 0;
	int len;

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

	realm = realm ? : ctx->realm;
	if ((code = krb5_build_principal(ctx, principal_out, strlen(realm), realm, princ_name, NULL)) != 0) {
		free(princ_name);
		return code;
	}
	free(princ_name);

	return 0;
}


void krb5_free_principal(krb5_context ctx __attribute ((unused)), krb5_principal principal) {
	int i;

	if (check_principal(principal) != 0) {
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
	if (val) val[0] = '\0'; // to test memory
	free(val);
}


/**
 * Build principal from variable string arguments
 *
 * Fake implementation is simplified - without "/".
 *
 * Principal "S@R" will be created by:
 *
 *   krb5_build_principal(ctx, &principal, strlen("R"), "R", "S", NULL)
 */
krb5_error_code krb5_build_principal(krb5_context ctx, krb5_principal *principal, unsigned int rlen, const char * realm, ...)
{
	va_list ap;
	krb5_error_code code;

	va_start(ap, realm);
	code = krb5_build_principal_alloc_va(ctx, principal, rlen, realm, ap);
	va_end(ap);

	return code;
}


/**
 * Build principal from variable string arguments
 *
 * See krb5_build_principal().
 */
krb5_error_code krb5_build_principal_alloc_va(krb5_context ctx, krb5_principal *principal_out, unsigned int rlen, const char *realm, va_list ap) {
	krb5_data *data = calloc(sizeof(*data), 1);
	krb5_principal principal = calloc(sizeof(*principal), 1);
	char *princ_name = va_arg(ap, char *);

	if (!realm) {
		realm = ctx->realm;
		rlen = ctx->rlen;
	}
	if (rlen != strlen(realm)) return ERROR_BAD_REALM;

	data[0].magic = MAGIC_DATA;
	data[0].data = strdup(princ_name);
	data[0].length = strlen(princ_name);

	principal->magic = MAGIC_PRINC;
	principal->realm.magic = MAGIC_DATA;
	principal->realm.data = strdup(realm);
	principal->realm.length = rlen;
	principal->data = data;
	principal->length = 1;

	*principal_out = principal;

	return 0;
}


const char *krb5_get_error_message(krb5_context ctx __attribute ((unused)), krb5_error_code code) {
	if (code < 0 || code > LAST_ERROR_CODE) code = LAST_ERROR;

	return strdup(errors[code]);
}


void krb5_free_error_message(krb5_context ctx __attribute ((unused)), const char *msg) {
	char *s = (char *)msg;

	if (s) s[0] = '\0'; // to test memory
	free(s);
}


/*
 * ========================
 * KADM5 API fake functions
 * ========================
 */

/**
 * Initialize context and load fake testing data
 *
 * Call krb5_free_context() to free.
 */
krb5_error_code kadm5_init_krb5_context(krb5_context *pctx) {
	krb5_error_code code;
	krb5_context ctx = calloc(sizeof(_krb5_context), 1);
	char *path = getenv("FAKE_KADM5_DATA") ? : DEFAULT_FAKE_KADM5_DATA;
	char *realm = getenv("FAKE_KADM5_REALM") ? : DEFAULT_REALM;

#ifdef FAKE_PTHREAD
	if (pthread_mutex_init(&ctx->lock, NULL) != 0) return ERROR_INIT;
#endif
	if ((code = db_load(ctx, path)) != 0) {
		free(ctx);
		return code;
	}
	if (!ctx->n) return ERROR_PARSE_DATA_FILE;

	ctx->realm = strdup(realm);
	ctx->rlen = strlen(realm);
	asprintf(&ctx->admin_name, "%s@%s", ctx->db[0].name, ctx->realm);
	ctx->admin_password = ctx->db[0].password ? strdup(ctx->db[0].password) : NULL;

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
	if (strcmp(ctx->admin_name, client_name) != 0) return ERROR_LOGIN_FAILED;
	if (pass) {
		if (strcmp(ctx->admin_password, pass) != 0) return ERROR_LOGIN_FAILED;
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
	if (strcmp(ctx->admin_name, client_name) != 0) return ERROR_LOGIN_FAILED;

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
	_kadm5_handle *handle = server_handle;
	_krb5_context *ctx = handle->ctx;

	return db_get(ctx, ent, principal);
}


kadm5_ret_t kadm5_free_principal_ent(
	void *server_handle,
	kadm5_principal_ent_t ent)
{
	_kadm5_handle *handle = server_handle;
	_krb5_context *ctx = handle->ctx;

	krb5_free_principal(ctx, ent->principal);
	if (ent->mod_name)
		krb5_free_principal(ctx, ent->mod_name);
	free(ent->policy);
	memset(ent, 0, sizeof(*ent));

	return 0;
}


kadm5_ret_t kadm5_create_principal(
	void *server_handle,
	kadm5_principal_ent_t ent,
	long mask,
	char *pass)
{
	_kadm5_handle *handle = server_handle;
	_krb5_context *ctx = handle->ctx;

	return db_put(ctx, ent, mask, pass);
}


kadm5_ret_t kadm5_delete_principal(
	void *server_handle,
	krb5_principal principal)
{
	_kadm5_handle *handle = server_handle;
	_krb5_context *ctx = handle->ctx;

	return db_remove(ctx, principal);
}


kadm5_ret_t kadm5_modify_principal(
	void *server_handle,
	kadm5_principal_ent_t ent,
	long mask)
{
	_kadm5_handle *handle = server_handle;
	_krb5_context *ctx = handle->ctx;

    return db_modify(ctx, ent, mask);
}


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

	LOCK(ctx);
	i = fake_search(ctx, new);
	if (i != -1) {
		UNLOCK(ctx);
		return ERROR_ALREADY_EXISTS;
	}

	i = fake_search(ctx, old);
	if (i == -1) {
		UNLOCK(ctx);
		return ERROR_UNKNOWN_PRINCIPAL;
	}

	free(ctx->db[i].name);
	ctx->db[i].name = strdup(new->data[0].data);

	UNLOCK(ctx);
	return 0;
}


/**
 * Get available principals.
 *
 * Query expression is handled by fnmatch.
 */
kadm5_ret_t kadm5_get_principals(
	void *server_handle,
	char *exp,
	char ***princs,
	int *count)
{
	int i, j;
	char *name;
	_kadm5_handle *handle = server_handle;
	_krb5_context *ctx = handle->ctx;

	LOCK(ctx);
	*princs = calloc(sizeof(char *), ctx->n);
	for (i = 0, j = 0; i < (int)ctx->n; i++) {
		asprintf(&name, "%s@%s", ctx->db[i].name, handle->realm);
		if (!exp || (fnmatch(exp, name, 0) == 0)) {
			(*princs)[j++] = name;
		}
	}
	*count = j;
	UNLOCK(ctx);

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


kadm5_ret_t kadm5_chpass_principal(
	void *server_handle,
	krb5_principal principal,
	char *pass)
{
	int i;
	_kadm5_handle *handle = server_handle;
	_krb5_context *ctx = handle->ctx;

	if (check_principal(principal) != 0) return ERROR_BAD_DATA;

	LOCK(ctx);
	i = fake_search(ctx, principal);
	if (i == -1) return ERROR_UNKNOWN_PRINCIPAL;

	free(ctx->db[i].password);
	ctx->db[i].password = pass ? strdup(pass) : NULL;
	UNLOCK(ctx);

	return 0;
}
