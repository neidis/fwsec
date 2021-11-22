// Asiacrypto 2000 version

#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <time.h>
FILE* file;

#define l 160

BIGNUM* phi;

struct FwSecSigPubKey {
	int T;
	BIGNUM* U;
	BIGNUM* N;
	BIGNUM* R;
	BIGNUM* Y;
}* gPubKey;

struct FwSecSigPriKey {
	int i;
	BIGNUM* S;
}* gPriKey;

struct FwSecSigSign {
	int i;
	BIGNUM* Z;
	BIGNUM* Y;
};

int gRSALength;		// k

BN_CTX* ctx;

void initializeStructures()
{
	// public key
	gPubKey->U = BN_new();
	gPubKey->N = BN_new();
	gPubKey->R = BN_new();
	gPubKey->Y = BN_new();

	// private key
	gPriKey->S = BN_new();
}
	

void hash(BIGNUM* r, int a, BIGNUM* b, BIGNUM* c)
{
	char hash_digest[SHA_DIGEST_LENGTH];
	char temp[2048];
	SHA_CTX sha_ctx;
	SHA1_Init(&sha_ctx);

	sprintf(temp,"%x",a);
	SHA1_Update(&sha_ctx, temp, strlen(temp));

	BN_bn2bin(b, temp);
	SHA1_Update(&sha_ctx, temp, BN_num_bytes(b));

	BN_bn2bin(c, temp);
	SHA1_Update(&sha_ctx, temp, BN_num_bytes(c));

	SHA1_Final(hash_digest, &sha_ctx);

	BN_bin2bn(hash_digest, l/8, r);
}

// sign
void hash_exp_mul(BIGNUM* sign, BIGNUM* r, BIGNUM* x, int i, BIGNUM* m, BIGNUM* R)
{
	BIGNUM* c = BN_new();
	hash(c, i, m, R);

	BIGNUM* t1 = BN_new();
	BN_mod_exp(t1, x, c, gPubKey->N, ctx); 
	BN_mod_mul(sign, r, t1, gPubKey->N, ctx);

	BN_free(c);
	BN_free(t1);
}

void exp_twos_power(BIGNUM* y, BIGNUM* x, int n)
{
	// y = x^u^i
	BIGNUM* t1 = BN_new();
	BN_copy(t1,x);

	int i;
	for(i=0; i<n; i++) {
		BN_mod_mul(y, t1, t1, gPubKey->N, ctx);
		BN_copy(t1, y);
	}

	BN_free(t1);
}

int setup()
{
	BIGNUM* t1 = BN_new();
	BIGNUM* t2 = BN_new();
	BIGNUM* t3 = BN_new();

	// key generate
	RSA* rsa;

	// p,q <-- Z, N=pq
	rsa = RSA_generate_key(gRSALength, 5, NULL, NULL);
        if(RSA_check_key(rsa) != 1) {
               perror("not gnerate RSA key");
               exit(0);
	}

	BN_copy(gPubKey->N,rsa->n);

        // generate R and compute Y <- R^{2^{l*(T+1)}}
        BN_rand_range(gPubKey->R, gPubKey->N);
        exp_twos_power(gPubKey->Y, gPubKey->R, (gPubKey->T+1)*l);

	// S0 <-- Z_N
	BN_rand_range(gPriKey->S, gPubKey->N);

	// U <-- 1/S^{2^{l(T+1)}}
	//BN_set_word(t2, 2);
	//BN_set_word(t3, l*(gPubKey->T+1));
	exp_twos_power(t1, gPriKey->S, l*(gPubKey->T+1));
//	multi_exp(t1, gPriKey->S, t2, t3);
	BN_mod_inverse(gPubKey->U, t1, gPubKey->N, ctx);
	
	gPriKey->i = 0;

	BN_free(t1);
	BN_free(t2);
	BN_free(t3);
	RSA_free(rsa);

	return 0;
}

int fastSetup()
{
	BIGNUM* t1 = BN_new();
	BIGNUM* t2 = BN_new();
	BIGNUM* t3 = BN_new();

	// safe RSA is generated
	// p<--2p'+1; p' <-- 2p''+1; p, p', p'' are primes
	// q<--2q'+1; q' <-- 2q''+1; q, q', q'' are primes
	// p,q <-- Z, N=pq
	BIGNUM* p = BN_new();
	BIGNUM* q = BN_new();

	BN_generate_prime_ex(p, gRSALength/2, 1, NULL, NULL, NULL);
	BN_generate_prime_ex(q, gRSALength/2, 1, NULL, NULL, NULL);

	BN_mul(gPubKey->N, p, q, ctx);

	// use phi(N)
	phi = BN_new();
	BN_sub(t1, p, BN_value_one());
	BN_sub(t2, q, BN_value_one());
	BN_mul(phi,t1, t2,ctx);

	// 2^{l(T+1)} mod phi(N)
	BN_set_word(t1, 2);
	BN_set_word(t2, l*(gPubKey->T+1));
	BN_mod_exp(t3, t1, t2, phi,ctx);

        // generate R and compute Y <- R^{2^{l*(T+1)}}
        BN_rand_range(gPubKey->R, gPubKey->N);
	BN_mod_exp(gPubKey->Y, gPubKey->R, t3, gPubKey->N,ctx);
	
	// S0 <-- Z_N
	BN_rand_range(gPriKey->S, gPubKey->N);

	// U <-- 1/S^{2^{l(T+1)}}
	BN_mod_exp(t1, gPriKey->S, t3, gPubKey->N ,ctx);
	BN_mod_inverse(gPubKey->U, t1, gPubKey->N, ctx);
	
	gPriKey->i = 0;

	BN_free(t1);
	BN_free(t2);
	BN_free(t3);
	BN_free(p);
	BN_free(q);

	return 0;
}


void signMessage(struct FwSecSigSign* sign, BIGNUM* m)
{
	BIGNUM* t1 = BN_new();

        // e <- {0,1}^l
        BIGNUM* e = BN_new();
        BN_rand(e, l, 1, 1);
	//BN_generate_prime_ex(e, l, 0, NULL, NULL, NULL);

        // R' <-- R^e
        BIGNUM* R = BN_new();
        BN_mod_exp(R, gPubKey->R, e, gPubKey->N, ctx);

	// Y' <-- Y^e
        BN_mod_exp(sign->Y, gPubKey->Y, e, gPubKey->N, ctx);

	// sigma <-- H(..)
        BIGNUM* sigma = BN_new();
	hash(sigma, gPriKey->i, sign->Y, m);

	// Z <-- RS^sigma
	BN_mod_exp(t1, gPriKey->S, sigma, gPubKey->N, ctx);
	BN_mod_mul(sign->Z, R, t1, gPubKey->N, ctx);

	sign->i = gPriKey->i;
	BN_free(t1);
	BN_free(e);
	BN_free(R);
	BN_free(sigma);
}

void update()
{
	if(gPriKey->i == gPubKey->T-1) return;

	// update secret key
	// i++
	gPriKey->i ++;

	// S_i^{2^l}
	BIGNUM* t1 = BN_new();
	BIGNUM* t2 = BN_new();
	BIGNUM* t3 = BN_new();
	//BN_set_word(t2, 2);
	//BN_set_word(t3, l);
	exp_twos_power(t1, gPriKey->S, l);
	//multi_exp(t1, gPriKey->S,t2, t3);
	BN_copy(gPriKey->S, t1);

	BN_free(t1);
	BN_free(t2);
	BN_free(t3);
}

void allocSign(struct FwSecSigSign* sign)
{
	sign->Z = BN_new();
	sign->Y = BN_new();
}


int verify(struct FwSecSigSign* sign, BIGNUM** m, struct FwSecSigPubKey* pubKey)
{
	BIGNUM* sigma = BN_new();
	BIGNUM* Y = BN_new();
	BIGNUM* t1 = BN_new();
	BIGNUM* t2 = BN_new();
	BIGNUM* t3 = BN_new();
	BIGNUM* t4 = BN_new();

	// Y' <-- Z^{2^{l*(T+1)}} U^sigma
	//BN_set_word(t2,2);
	//BN_set_word(t3, l*(pubKey->T+1-sign->i));
	exp_twos_power(t1, sign->Z, l*(pubKey->T+1-sign->i));
	hash(sigma, sign->i, sign->Y, m[0]);
	BN_mod_exp(t2, pubKey->U, sigma, pubKey->N, ctx);
//	BN_mod_inverse(t3, t2, pubKey->N, ctx);
	BN_mod_mul(t4, t1, t2, pubKey->N, ctx);
	if(sign->i>0)
		exp_twos_power(Y, t4, l*(sign->i));
	else BN_copy(Y, t4);

	int flag = (BN_cmp(Y, sign->Y)==0);

	BN_free(Y);
	BN_free(t1);
	BN_free(t2);
	BN_free(t3);
	BN_free(t4);

	return flag;
}

int batVerify(struct FwSecSigSign* sign, BIGNUM** m, struct FwSecSigPubKey* pubKey, int theNumber)
{
	BIGNUM* Y = BN_new();
	BIGNUM* V = BN_new();
	BIGNUM* W = BN_new();
	BIGNUM* Z = BN_new();
	BIGNUM* t1 = BN_new();
	BIGNUM* t2 = BN_new();
	BIGNUM* t3 = BN_new();
	BIGNUM* t4 = BN_new();

	int i;
	
	// V <-- 1
	BN_set_word(V,1);
	exp_twos_power(W, pubKey->U, l * (pubKey->T +1 - theNumber));

	BN_set_word(Z,1);
	for(i=0; i<theNumber; i++) {
		// Z <-- \prod_{i=1}^{theNumber} Z_i
		BN_mod_mul(Z, Z, sign->Z, pubKey->N, ctx);

		hash(t1, 0, sign->Y, m[0]);
		BN_mod_exp(t2, W, t1, pubKey->N,ctx);
		BN_mod_mul(t3, sign->Y, t2, pubKey->N, ctx);
		BN_mod_mul(V, V, t3, pubKey->N, ctx);

		exp_twos_power(W, W, l);
	}

	// if V==Z^{2^{l(T+1)}}
	exp_twos_power(t1, Z, l*(pubKey->T+1));

	int flag = (BN_cmp(V,t1)==0);

	BN_free(Y);
	BN_free(Z);
	BN_free(V);
	BN_free(W);
	BN_free(t1);
	BN_free(t2);
	BN_free(t3);
	BN_free(t4);

	return flag;
}

int main(int argc, const char* argv[])
{
	clock_t start, end;

	ctx = BN_CTX_new();
//	file = fopen("output.txt","w");

	gPubKey = malloc(sizeof(struct FwSecSigPubKey));
	gPriKey = malloc(sizeof(struct FwSecSigPriKey));

	initializeStructures();

	// argument : rsa_bit_length period_length hash_size
	if(argc < 3) return 0;
	gRSALength = atoi(argv[1]);	// k
	gPubKey->T = atoi(argv[2]);	// T

	printf("%d\t", gPubKey->T);
		
	start = clock();
	//setup();
	fastSetup();
	end = clock();
	printf("%f\t", (float)(end-start)/CLOCKS_PER_SEC);

	// test
	struct FwSecSigSign **sign;
	BIGNUM** message;
//	sign = malloc(sizeof(struct FwSecSigSign*)*gPubKey->T);
//	message = malloc(sizeof(BIGNUM*)*gPubKey->T);
	sign = malloc(sizeof(struct FwSecSigSign*));
	message = malloc(sizeof(BIGNUM*));

	int i;
	char* tempMsg = malloc(SHA_DIGEST_LENGTH);
//	for(i=0; i<gPubKey->T; i++) {
	for(i=0; i<1; i++) {
		sign[i] = malloc(sizeof(struct FwSecSigSign));
		allocSign(sign[i]);

		message[i] = BN_new();
		
		RAND_bytes(tempMsg, SHA_DIGEST_LENGTH);
		BN_bin2bn(tempMsg, SHA_DIGEST_LENGTH, message[i]);
	}

	start = clock();

	// sign and update
//	for(i=0; i<gPubKey->T; i++) {
	for(i=0; i<1; i++) {
		signMessage(sign[0], message[0]);
	end = clock();
	printf("%f\t", (float)(end-start)/CLOCKS_PER_SEC);
	start = clock();
//		signMessage(sign[i], message[i]);
		update();
	}

	end = clock();
	printf("%f\t", (float)(end-start)/CLOCKS_PER_SEC);

	start = clock();
	// verification for each sign	
	//for(i=0; i<gPubKey->T; i++) {
	for(i=0; i<1; i++) {
		if(!verify(sign[i], &message[i], gPubKey)) {
			printf("sign[%d] is invalid\n", i);
		}
	}
	end = clock();
	printf("%f\t", (float)(end-start)/CLOCKS_PER_SEC);

	start = clock();
	batVerify(sign[0], &message[0], gPubKey, atoi(argv[3]));
	end = clock();
	printf("%f\n", (float)(end-start)/CLOCKS_PER_SEC);

	BN_free(phi);
}
