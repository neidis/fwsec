// Crypto 2001 version using relative primes

#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <time.h>
FILE* file;

struct FwSecSigPubKey {
	int T;
	BIGNUM* N;
	BIGNUM* v;
}* gPubKey;

struct FwSecSigPriKey {
	int i;
	BIGNUM* s;
	BIGNUM* t;
	BIGNUM** e;
	int seed;
}* gPriKey;

struct FwSecSigSign {
	int i;
	BIGNUM* z;
	BIGNUM* sigma;
	BIGNUM* e;
};

int gRSALength;		// k
int l = SHA_DIGEST_LENGTH;
int gNumPeriod;	// T

BN_CTX* ctx;

void initializeStructures()
{
	// public key
	gPubKey->N = BN_new();
	gPubKey->v = BN_new();

	// private key
	gPriKey->s = BN_new();
	gPriKey->t = BN_new();
	gPriKey->seed = 0;

	gPriKey->e = malloc(sizeof(BIGNUM*)*gNumPeriod);

	for(int i=0; i<gNumPeriod; i++) {
		// private key
		gPriKey->e[i] = BN_new();
	}
}
	

void hash(BIGNUM* r, int i, BIGNUM* a, BIGNUM* b, BIGNUM* c)
{
	char hash_digest[SHA_DIGEST_LENGTH];
	char temp[2048];
	SHA_CTX sha_ctx;
	SHA1_Init(&sha_ctx);

	sprintf(temp, "%x", i);
	SHA1_Update(&sha_ctx, temp, strlen(temp));

	BN_bn2bin(a, temp);
	SHA1_Update(&sha_ctx, temp, BN_num_bytes(a));

	BN_bn2bin(b, temp);
	SHA1_Update(&sha_ctx, temp, BN_num_bytes(b));

	BN_bn2bin(c, temp);
	SHA1_Update(&sha_ctx, temp, BN_num_bytes(c));

	SHA1_Final(hash_digest, &sha_ctx);

	BN_bin2bn(hash_digest, SHA_DIGEST_LENGTH, r);
}

int isRelativePrime(BIGNUM** es, int bound)
{
	BIGNUM* t1 = BN_new();
	for(int i=0; i<bound; i++) {
		BN_gcd(t1, es[i], es[bound],ctx);
		if(!BN_is_one(t1)) return 0;
	}

	return 1;
}

void generateRelativePrime(BIGNUM** e, int seed)
{
	//BN_GENCB *cb = BN_GENCB_new();
	for(int i=0; i<gPubKey->T; i++)
		BN_generate_prime_ex(e[i], l, 0, NULL, NULL, NULL);

	//BN_GENCB_free(cb);
		
/*
	BIGNUM* t1 = BN_new();
	srand(seed);
	for(int i=0; i<gPubKey->T; i++) {
		while(1) {
			BN_rand(e[i], l, 0, 1);
			if(isRelativePrime(e, i)) {
				break;
			}
		}
	}
*/
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

	BIGNUM* phi = BN_new();
	BN_one(t1);
	BN_sub(t2, rsa->p, t1);
	BN_sub(t3, rsa->q, t1);
	BN_mul(phi, t2, t3, ctx);
	 
	BN_copy(gPubKey->N,rsa->n);

	// e1, ..., eT
	generateRelativePrime(gPriKey->e,gPriKey->seed);

	// t1 <-- Z_N
	BN_rand_range(t1, gPubKey->N);

	// f2
	BIGNUM* f2 = BN_new();
	BN_one(f2);
	for(int i=1; i<gPubKey->T; i++) {
		BN_mod_mul(t1, f2, gPriKey->e[i], phi, ctx);
		BN_copy(f2,t1); 
	}

	// s1<-- t1^f2
	BN_mod_exp(gPriKey->s, t1, f2, gPubKey->N, ctx);
	
	// v <-- 1/s1^e1
	BN_mod_exp(t3, gPriKey->s, gPriKey->e[0], gPubKey->N, ctx);
	BN_mod_inverse(gPubKey->v, t3, gPubKey->N, ctx);

	// t2 <-- t1^e1
	BN_mod_exp(gPriKey->t, t1, gPriKey->e[0], gPubKey->N, ctx);

	gPriKey->i = 0;

	BN_free(t1);
	BN_free(t2);
	BN_free(t3);
	BN_free(phi);
	BN_free(f2);
	RSA_free(rsa);

	return 0;
}

void signMessage(struct FwSecSigSign* sign, BIGNUM* m)
{
	BIGNUM* t1 = BN_new();
	BIGNUM* t2 = BN_new();
	BIGNUM* t3 = BN_new();
	BIGNUM* t4 = BN_new();
	BIGNUM* c = BN_new();

	// r <-- Z_N
	BIGNUM* r = BN_new();
	BN_rand_range(r, gPubKey->N);

	// y <-- r^{ei}
	BIGNUM* y = BN_new();
	BIGNUM* e = gPriKey->e[gPriKey->i];
	BN_mod_exp(y, r, e, gPubKey->N, ctx);

	// sigma <-- H(i, ei, y, m)
	hash(sign->sigma, gPriKey->i, e, y, m);

	// z <-- rs^sigma
	BN_mod_exp(t1, gPriKey->s, sign->sigma, gPubKey->N, ctx);
	BN_mod_mul(sign->z, r, t1, gPubKey->N, ctx);

	sign->i = gPriKey->i;
	BN_copy(sign->e, e);
}

void update()
{
	if(gPriKey->i == gPubKey->T-1) return;

	// update secret key

	int i;

	BIGNUM** es;
	es = malloc(sizeof(BIGNUM*)*gPubKey->T);
	for(i=0; i< gPubKey->T; i++) {
		es[i] = BN_new();
	}

	// just for time consuming
	generateRelativePrime(es, gPriKey->seed);

	// sj+1 <-- tj+1 ^ ej+2 .. eT
	BIGNUM* t1 = BN_new();
	BIGNUM* t2 = BN_new();
	BN_copy(t1, gPriKey->t);
	for(i=gPriKey->i+2; i<gPubKey->T; i++) {
		BN_mod_exp(t2, t1, gPriKey->e[i], gPubKey->N, ctx);
		BN_copy(t1,t2);
	} 
	BN_copy(gPriKey->s, t1);

	BN_mod_exp(t1, gPriKey->t, gPriKey->e[gPriKey->i+1], gPubKey->N, ctx);
	BN_copy(gPriKey->t, t1);

	// i++
	gPriKey->i ++;

	BN_free(t1);
	BN_free(t2);

	for(i=0; i< gPubKey->T; i++) {
		BN_free(es[i]);
	}
	free(es);
}

void allocSign(struct FwSecSigSign* sign)
{
	sign->z = BN_new();
	sign->sigma = BN_new();
	sign->e = BN_new();
}


int verify(struct FwSecSigSign* sign, BIGNUM** m, struct FwSecSigPubKey* pubKey)
{
	BIGNUM* y = BN_new();
	BIGNUM* c = BN_new();
	BIGNUM* t1 = BN_new();
	BIGNUM* t2 = BN_new();

	// y' <-- z^e v^sigma
	BN_mod_exp(t1, sign->z, sign->e, pubKey->N, ctx);
	BN_mod_exp(t2, pubKey->v, sign->sigma, pubKey->N, ctx);
	BN_mod_mul(y, t1, t2, pubKey->N, ctx);

	hash(c, sign->i, sign->e, y, m[0]);
	
	int flag = (BN_cmp(sign->sigma, c)==0);

	BN_free(y);
	BN_free(c);
	BN_free(t1);
	BN_free(t2);

	return flag;
}

int main(int argc, const char* argv[])
{
	clock_t start, end;

	ctx = BN_CTX_new();
//	file = fopen("output.txt","w");

	gPubKey = malloc(sizeof(struct FwSecSigPubKey));
	gPriKey = malloc(sizeof(struct FwSecSigPriKey));


	// argument : rsa_bit_length period_length hash_size
	if(argc < 3) return 0;
	gRSALength = atoi(argv[1]);	// k
	gNumPeriod = atoi(argv[2]);	// T

	initializeStructures();

	gPubKey->T = gNumPeriod;

	printf("%d\t", gPubKey->T);
		
	start = clock();
	setup();
	end = clock();
	printf("%f\t", (float)(end-start)/CLOCKS_PER_SEC);

	// test
	struct FwSecSigSign **sign;
	BIGNUM** message;
	sign = malloc(sizeof(struct FwSecSigSign*)*gPubKey->T);
	message = malloc(sizeof(BIGNUM*)*gPubKey->T);

	int i;
	char* tempMsg = malloc(SHA_DIGEST_LENGTH);
	for(i=0; i<gPubKey->T; i++) {
		sign[i] = malloc(sizeof(struct FwSecSigSign));
		allocSign(sign[i]);

		message[i] = BN_new();
		
		RAND_bytes(tempMsg, SHA_DIGEST_LENGTH);
		BN_bin2bn(tempMsg, SHA_DIGEST_LENGTH, message[i]);
	}

	start = clock();

	// sign and update
	for(i=0; i<gPubKey->T; i++) {
		signMessage(sign[i], message[i]);
		update();
	}

	end = clock();
	printf("%f\t", (float)(end-start)/CLOCKS_PER_SEC);

	start = clock();
	// verification for each sign	
	for(i=0; i<gPubKey->T; i++) {
		if(!verify(sign[i], &message[i], gPubKey)) {
			printf("sign[%d] is invalid\n", i);
		}
	}
	end = clock();
	printf("%f\t", (float)(end-start)/CLOCKS_PER_SEC);

	// size of sign
	printf("%d\n", BN_num_bytes(sign[0]->z)+BN_num_bytes(sign[0]->sigma)+BN_num_bytes(sign[0]->e)+sizeof(int));
}
