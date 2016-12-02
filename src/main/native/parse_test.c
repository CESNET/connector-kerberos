#include <stdio.h>

#include <kadm5/admin.h>


static char *check(krb5_context ctx, long code) {
	const char *krbmsg;
	char *text;

	if (ctx) {
		krbmsg = krb5_get_error_message(ctx, code);
		asprintf(&text, "Kerberos error %ld: %s", code, krbmsg);
		krb5_free_error_message(ctx, krbmsg);
	} else {
		asprintf(&text, "Kerberos error %ld: (no details)", code);
	}

	return text;
}


int main() {
	krb5_context ctx;
	krb5_principal principal;
	int err = 0;
	char *msg;
	size_t i;
	const char *test_principals[] = {
		"hawking@EARTH",
		"hawking@EARTH2@EARTH1",
		"hawking\\@EARTH1@EARTH2",
		"hawking",
		"\\h\\awking",
	};

	if ((err = kadm5_init_krb5_context(&ctx))) {
		printf("Init failed: code %d\n", err);
		return err;
	}

	for (i = 0; i < sizeof(test_principals) / sizeof(char *); i++) {
		err = krb5_parse_name(ctx, test_principals[i], &principal);
		if (err) {
			msg = check(ctx, err);
			printf("%s\n", msg);
			free(msg);
			goto end;
		}

		printf("principal: %s\n", test_principals[i]);
		printf("name: %s\n", principal->data[0].data);
		printf("realm: %s\n", principal->realm.data);
		printf("\n");

		krb5_free_principal(ctx, principal);
	}

end:
	krb5_free_context(ctx);
	return err;
}
