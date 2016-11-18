#define CC /*
gcc -I. -D_GNU_SOURCE -W -Wall -g -O0 $0 -o krbconn_test -lkrb5 -lkadm5clnt_mit
exit $?
*/
#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <profile.h>
#include "kerberos.h"


char *krbconn_error(krbconn_context_t *ctx, krb5_error_code code) {
	const char *krbmsg;
	char *text;

	if (ctx->krb) {
		krbmsg = krb5_get_error_message(ctx->krb, code);
		asprintf(&text, "Kerberos error %d: %s", code, krbmsg);
		krb5_free_error_message(ctx->krb, krbmsg);
	} else {
		asprintf(&text, "Kerberos error %d: (no details)", code);
	}

	return text;
}


krb5_error_code krbconn_init(krbconn_context_t *ctx, krbconn_config_t *config) {
	krb5_context krb = NULL;
	krb5_error_code code;
	//krb5_ccache ccache;
	kadm5_config_params params;
	void *handle = NULL;

	memset(ctx, 0, sizeof(*ctx));
	code = kadm5_init_krb5_context(&krb);
	if (code != 0) return code;
	ctx->krb = krb;

	if (!config->realm) {
		char *realm;

		code = krb5_get_default_realm(krb, &realm);
		if (code != 0) return code;
		config->realm = strdup(realm);
		krb5_free_default_realm(krb, realm);
	}

	memset(&params, 0, sizeof params);
	params.mask |= KADM5_CONFIG_REALM;
	params.realm = config->realm;
	if (config->keytab) {
		code = kadm5_init_with_skey(ctx->krb, config->principal, config->keytab, NULL, &params, KADM5_STRUCT_VERSION, KADM5_API_VERSION_4, NULL, &handle);
	} else if (config->password) {
		code = kadm5_init_with_password(ctx->krb, config->principal, config->password, NULL, &params, KADM5_STRUCT_VERSION, KADM5_API_VERSION_4, NULL, &handle);
	}
	if (code != 0) return code;
	ctx->handle = handle;

	return 0;
}


static krb5_error_code krbconn_princ2str(krb5_context krb, krb5_principal principal, char **name) {
	char *s;
	krb5_error_code code;

	if ((code = krb5_unparse_name(krb, principal, &s)) != 0) return code;
	*name = strdup(s);
	krb5_free_unparsed_name(krb, s);

	return 0;
}


krb5_error_code krbconn_get(krbconn_context_t *ctx, char *princ_name, krbconn_principal_t *result) {
	krb5_error_code code;
	krb5_principal principal;
	kadm5_principal_ent_rec krbresult;

	code = krb5_parse_name(ctx->krb, princ_name, &principal);
	if (code) return code;

	code = kadm5_get_principal(ctx->handle, principal, &krbresult, KADM5_PRINCIPAL_NORMAL_MASK/* | KADM5_KEY_DATA*/);
	krb5_free_principal(ctx->krb, principal);
	if (code) return code;

	memset(result, 0, sizeof(*result));
	if ((code = krbconn_princ2str(ctx->krb, krbresult.principal, &result->name)) != 0) return code;

	kadm5_free_principal_ent(ctx->handle, &krbresult);

	return 0;
}


void krbconn_destroy(krbconn_context_t *ctx) {
	if (ctx->handle) kadm5_destroy(ctx->handle);
	if (ctx->krb) {
		struct _profile_t *profile;

		if (krb5_get_profile(ctx->krb, &profile) == 0) {
			profile_release(profile);
		} else {
			puts("profil nende");
		}
		krb5_free_context(ctx->krb);
	}
	memset(ctx, 0, sizeof(*ctx));
}


void krbconn_free_config(krbconn_config_t *config) {
	free(config->keytab);
	free(config->principal);
	free(config->password);
	free(config->realm);
}


void krbconn_free_principal(krbconn_principal_t *principal) {
	free(principal->name);
	free(principal->mod_name);
	memset(principal, 0, sizeof(*principal));
}


void usage(const char *name) {
	printf("Usage: %s [OPTIONS]\n\
OPTIONS are:\n\
  -h ............. usage\n\
  -k FILE ........ keytab file\n\
  -u PRINCIPAL ... admin principal\n\
  -p PASSWORD .... admin password\n\
", name);
}


int main(int argc, char **argv) {
	krbconn_config_t config;
	krbconn_context_t ctx;
	krb5_error_code code;
	char *err;
	krbconn_principal_t principal;
	char c;

	memset(&config, 0, sizeof config);
	while ((c = getopt(argc, argv, "hu:p:k:r:")) != -1) {
		switch(c) {
			case 'h':
				usage(argv[0]);
				return 0;
			case 'k':
				config.keytab = strdup(optarg);
				break;
			case 'u':
				config.principal = strdup(optarg);
				break;
			case 'p':
				config.password = strdup(optarg);
				break;
			case 'r':
				config.realm = strdup(optarg);
				break;
		}
	}
	if (!config.keytab && !config.password) {
		usage(argv[0]);
		printf("\n");
		printf("Keytab file or password required\n");
		krbconn_free_config(&config);
		return 1;
	}

	if ((code = krbconn_init(&ctx, &config)) != 0) {
		err = krbconn_error(&ctx, code);
		printf("%s\n", err);
		free(err);
		return code;
	}

	if ((code = krbconn_get(&ctx, "majlen", &principal))) {
		err = krbconn_error(&ctx, code);
		printf("%s\n", err);
		free(err);
		return code;
	}
	printf("Principal: %s\n", principal.name);
	krbconn_free_principal(&principal);

	krbconn_destroy(&ctx);
	krbconn_free_config(&config);
	return 0;
}
