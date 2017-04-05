#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "kerberos.h"


#define DEFAULT_PRINCIPAL "host/pokuston"


void usage(const char *name) {
	printf("Usage: %s [OPTIONS] [COMMAND]\n\
OPTIONS:\n\
  -h ............. usage\n\
  -k FILE ........ keytab file\n\
  -u PRINCIPAL ... admin principal\n\
  -p PASSWORD .... admin password\n\
  -r REALM ....... Kerberos realm\n\
\n\
COMMAND:\n\
  get [PRINCIPAL]\n\
  create [PRINCIPAL]\n\
  delete [PRINCIPAL]\n\
  list [QUERY]\n\
  modify [PRINCIPAL] [POLICY]\n\
  rename PRINCIPAL NEW_PRINCIPAL\n\
  cpw PRINCIPAL PASSWORD\n\
  error CODE\n\
  renew [PRINCIPAL]\n\
", name);
}


int main(int argc, char **argv) {
	krbconn_config_t config;
	krbconn_context_t ctx;
	long code = 0;
	char *err;
	krbconn_principal_t principal;
	char c;
	const char *command = "get";
	char *name = DEFAULT_PRINCIPAL;

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
	if (optind < argc) {
		command = argv[optind++];
	}
	if (!config.principal) {
		usage(argv[0]);
		printf("\n");
		printf("Admin principal name required\n");
		krbconn_free_config(&config);
		return 1;
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
		printf("%ld: %s\n", code, err);
		free(err);
		goto end;
	}

	if (strcmp(command, "get") == 0) {
		if (optind < argc) {
			name = argv[optind++];
		}
		if ((code = krbconn_get(&ctx, name, &principal)) != 0) {
			err = krbconn_error(&ctx, code);
			printf("%s, principal '%s'\n", err, name);
			free(err);
			goto end;
		}
		printf("Principal:       %s\n", principal.name);
		printf("Expire:          %s", ctime(&principal.princ_expire));
		printf("Modified:        %s", ctime(&principal.mod_date));
		printf("Modified by:     %s\n", principal.mod_name);
		printf("Password change: %s", ctime(&principal.pwd_change));
		printf("Password expire: %s", ctime(&principal.pwd_expire));
		printf("Attributes:      %d\n", principal.attributes);
		printf("Policy:          %s\n", principal.policy);
		krbconn_free_principal(&principal);
	} else if (strcmp(command, "create") == 0) {
		if (optind < argc) {
			name = argv[optind++];
		}

		memset(&principal, 0, sizeof principal);
		principal.name = name;
		principal.policy = "default_nohistory";
		if ((code = krbconn_create(&ctx, &principal, KRBCONN_POLICY, NULL))) {
			err = krbconn_error(&ctx, code);
			printf("%s\n", err);
			free(err);
			goto end;
		}
		printf("%s created\n", principal.name);
	} else if (strcmp(command, "delete") == 0) {
		if (optind < argc) {
			name = argv[optind++];
		}
		principal.name = name;
		if ((code = krbconn_delete(&ctx, principal.name))) {
			err = krbconn_error(&ctx, code);
			printf("%s, principal '%s'\n", err, name);
			free(err);
			goto end;
		}
		printf("%s deleted\n", principal.name);
	} else if (strcmp(command, "list") == 0) {
		char **list;
		const char *query = NULL;
		int i, count;

		if (optind < argc) {
			query = argv[optind++];
		}
		printf("Listing, query = %s\n", query);
		if ((code = krbconn_list(&ctx, query, &list, &count))) {
			err = krbconn_error(&ctx, code);
			printf("%s\n", err);
			free(err);
			goto end;
		}
		for (i = 0; i < count; i++) {
			printf("%s ", list[i]);
		}
		printf("\n");
		krbconn_free_list(&ctx, list, count);
	} else if (strcmp(command, "modify") == 0) {
		if (optind < argc) {
			name = argv[optind++];
		}

		memset(&principal, 0, sizeof principal);
		principal.name = name;
		if (optind < argc) {
			principal.policy = argv[optind++];
			if (strcmp(principal.policy, "NULL") == 0) principal.policy = NULL;
		} else {
			principal.policy = "default_nohistory";
		}
		printf("Principal:       %s\n", principal.name);
		printf("Attributes:      %d\n", principal.attributes);
		printf("Policy:          %s\n", principal.policy);
		if ((code = krbconn_modify(&ctx, &principal, KRBCONN_POLICY))) {
			err = krbconn_error(&ctx, code);
			printf("%s\n", err);
			free(err);
			goto end;
		}
		printf("%s modified\n", principal.name);
	} else if (strcmp(command, "rename") == 0) {
		char *new_name;

		if (optind + 2 < argc) {
			printf("Principal names required for 'rename' command\n");
			code = 1;
			goto end;
		}
		name = argv[optind++];
		new_name = argv[optind++];

		printf("Old name:        %s\n", name);
		printf("New name:        %s\n", new_name);
		if ((code = krbconn_rename(&ctx, name, new_name))) {
			err = krbconn_error(&ctx, code);
			printf("%s\n", err);
			free(err);
			goto end;
		}
		printf("%s renamed to %s\n", name, new_name);
	} else if (strcmp(command, "cpw") == 0) {
		if (optind < argc) {
			name = argv[optind++];
		}
		if (optind >= argc) {
			printf("Password argument required for 'cpw' command\n");
			code = 1;
			goto end;
		}
		printf("Principal:       %s\n", name);
		if ((code = krbconn_chpass(&ctx, name, argv[optind]))) {
			err = krbconn_error(&ctx, code);
			printf("%s\n", err);
			free(err);
			goto end;
		}
		printf("Password of %s changed\n", name);
	} else if (strcmp(command, "error") == 0) {
		long code = 0;

		if (optind < argc) {
			code = atol(argv[optind++]);
		}
		err = krbconn_error(&ctx, code);
		printf("Error code: %ld\n", code);
		printf("MIT Krb5 message: %s\n", err);
		free(err);
	} else if (strcmp(command, "renew") == 0) {
		if ((code = krbconn_renew(&ctx, &config)) != 0) {
			err = krbconn_error(&ctx, code);
			printf("%s\n", err);
			free(err);
			goto end;
		}
		printf("Renew of %s successfull\n", config.principal);
	}

end:
	krbconn_destroy(&ctx);
	krbconn_free_config(&config);
	return code;
}
