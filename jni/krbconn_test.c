#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "kerberos.h"


void usage(const char *name) {
	printf("Usage: %s [OPTIONS] [get|create]\n\
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
	long code = 0;
	char *err;
	krbconn_principal_t principal;
	char c;
	const char *command = "get";
	char *arg = "host/pokuston.civ.zcu.cz";

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
	if (optind < argc) {
		arg = argv[optind++];
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
		printf("%s\n", err);
		free(err);
		goto end;
	}

	if (strcmp(command, "get") == 0) {
		if ((code = krbconn_get(&ctx, arg, &principal)) != 0) {
			err = krbconn_error(&ctx, code);
			printf("%s, principal '%s'\n", err, arg);
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
		memset(&principal, 0, sizeof principal);
		principal.name = arg;
		principal.policy = "default_nohistory";
		if ((code = krbconn_create(&ctx, &principal, KRBCONN_POLICY, NULL))) {
			err = krbconn_error(&ctx, code);
			printf("%s\n", err);
			free(err);
			goto end;
		}
		printf("%s created\n", principal.name);
	} else if (strcmp(command, "delete") == 0) {
		principal.name = arg;
		if ((code = krbconn_delete(&ctx, principal.name))) {
			err = krbconn_error(&ctx, code);
			printf("%s, principal '%s'\n", err, arg);
			free(err);
			goto end;
		}
		printf("%s deleted\n", principal.name);
	} else if (strcmp(command, "list") == 0) {
		char **list;
		int i, count;

		if ((code = krbconn_list(&ctx, "*_adm", &list, &count))) {
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
		int mask = 0;

		memset(&principal, 0, sizeof principal);
		principal.name = arg;
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
	}

end:
	krbconn_destroy(&ctx);
	krbconn_free_config(&config);
	return code;
}
