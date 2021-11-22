#include <openssl/rsa.h>
#include <openssl/bn.h>

void main()
{
	BN_CTX* ctx = BN_CTX_new();
	RSA* key;

	key = RSA_generate_key(100,5, NULL,NULL);

	BIGNUM* m = BN_new();
	BIGNUM* c = BN_new();
	BIGNUM* result = BN_new();

	BN_set_word(m, 58);

	BN_mod_exp(c, m, key->e, key->n, ctx);
	BN_mod_exp(result, c, key->d, key->n, ctx);

	BN_print_fp(stdout, key->n);
	printf("\n");
	BN_print_fp(stdout, key->d);
	printf("\n");
	BN_print_fp(stdout, m);
	printf("\n");
	BN_print_fp(stdout, c);
	printf("\n");
	BN_print_fp(stdout, result);
}
