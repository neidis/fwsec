// Crypto 1999 version

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
	BIGNUM* N;
	BIGNUM* U[l];
	BIGNUM* R;
	BIGNUM* Y;
}* gPubKey;

struct FwSecSigPriKey {
	int i;
	BIGNUM* S[l];
}* gPriKey;

struct FwSecSigSign {
	int i;
	BIGNUM* Y;
	BIGNUM* Z;
};

int gRSALength;		// k

BN_CTX* ctx;

void initializeStructures()
{
	// public key
	gPubKey->N = BN_new();
	gPubKey->R = BN_new();
	gPubKey->Y = BN_new();


	for(int i=0; i<l; i++) {
		gPubKey->U[i] = BN_new();

		// private key
		gPriKey->S[i] = BN_new();
	}
}
	

void hash(BIGNUM* r, BIGNUM* a, BIGNUM* b, BIGNUM* c)
{
	char hash_digest[SHA_DIGEST_LENGTH];
	char temp[2048];
	SHA_CTX sha_ctx;
	SHA1_Init(&sha_ctx);

	BN_bn2bin(a, temp);
	SHA1_Update(&sha_ctx, temp, BN_num_bytes(a));

	BN_bn2bin(b, temp);
	SHA1_Update(&sha_ctx, temp, BN_num_bytes(b));

	BN_bn2bin(c, temp);
	SHA1_Update(&sha_ctx, temp, BN_num_bytes(c));

	SHA1_Final(hash_digest, &sha_ctx);

	BN_bin2bn(hash_digest, l/8, r);
}

void hash2(BIGNUM* r, int a, BIGNUM* b, BIGNUM* c)
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
void hash_exp_mul(BIGNUM* sign, BIGNUM* r, BIGNUM* x, BIGNUM* i, BIGNUM* m, BIGNUM* R)
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
        // y = x^(2^n)
        BIGNUM* t1 = BN_new();
        BN_copy(t1,x);
        BN_copy(y,x);

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

	// generate R and compute Y <- R^{2^{T+1}}
	BN_rand_range(gPubKey->R, gPubKey->N);
	exp_twos_power(gPubKey->Y, gPubKey->R, gPubKey->T+1);

	for(int i=0; i<l; i++) {

		// S_i <-- Z_N
		BN_rand_range(gPriKey->S[i], gPubKey->N);

		// U_i <-- S^{2^{T+1}}
		exp_twos_power(gPubKey->U[i], gPriKey->S[i], gPubKey->T+1);
	}
	
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
/*

        // key generate
        RSA* rsa;

        // p,q <-- Z, N=pq
        rsa = RSA_generate_key(gRSALength, 5, NULL, NULL);
        if(RSA_check_key(rsa) != 1) {
               perror("not gnerate RSA key");
               exit(0);
        }


        BN_copy(gPubKey->N,rsa->n);
*/
        // use phi(N)
        phi = BN_new();
        BN_sub(t1, p, BN_value_one());
        BN_sub(t2, q, BN_value_one());
        BN_mul(phi,t1, t2,ctx);

        // 2^{(T+1)} mod phi(N)
        BN_set_word(t1, 2);
        BN_set_word(t2, (gPubKey->T+1));
        BN_mod_exp(t3, t1, t2, phi,ctx);

        // generate R and compute Y <- R^{2^{(T+1)}}
        BN_rand_range(gPubKey->R, gPubKey->N);
        BN_mod_exp(gPubKey->Y, gPubKey->R, t3, gPubKey->N,ctx);

	for(int i=0; i<l; i++) {

		// S_i <-- Z_N
		BN_rand_range(gPriKey->S[i], gPubKey->N);

		// U_i <-- S^{2^{T+1}}
        	BN_mod_exp(gPubKey->U[i], gPriKey->S[i], t3, gPubKey->N ,ctx);
	}
	
        gPriKey->i = 0;

        BN_free(t1);
        BN_free(t2);
        BN_free(t3);
        //RSA_free(rsa);
        BN_free(p);
        BN_free(q);
        //BN_free(three);

	return 0;
}

void signMessage(struct FwSecSigSign* sign, BIGNUM* m)
{
	BIGNUM* t1 = BN_new();
	BIGNUM* t2 = BN_new();
	BIGNUM* t3 = BN_new();
	BIGNUM* c = BN_new();
	BIGNUM* k = BN_new();

	// k <- {0,1}^l
	BN_rand(k, l, 1, 1);

	// R' <-- R^k
	BIGNUM* R = BN_new();
	BN_mod_exp(R, gPubKey->R, k, gPubKey->N, ctx); 

	// Y' <-- Y^k
	BIGNUM* Y = BN_new();
	BN_mod_exp(Y, gPubKey->Y, k, gPubKey->N, ctx); 

	// c_i <-- H(..)
	BN_set_word(t1, gPriKey->i);
	hash(c, t1, Y, m);

	// Z <-- R PI S^c_i
	BN_one(t2);
	for(int i=0; i<l; i++) {
		if(BN_is_bit_set(c,i)) {
			BN_mod_mul(t1, t2, gPriKey->S[i], gPubKey->N, ctx);
			BN_copy(t2,t1);
		}
	}
	BN_mod_mul(sign->Z, R, t2, gPubKey->N, ctx);
	BN_copy(sign->Y, Y);

	sign->i = gPriKey->i;
}

void update()
{
	if(gPriKey->i == gPubKey->T) return;

	// update secret key
	// i++
	gPriKey->i ++;

	BIGNUM* t1 = BN_new();
	for(int i=0; i<l; i++) {
		BN_mod_mul(t1, gPriKey->S[i], gPriKey->S[i], gPubKey->N, ctx);
		BN_copy(gPriKey->S[i], t1);
	} 

	BN_free(t1);
}

void allocSign(struct FwSecSigSign* sign)
{
	sign->Z = BN_new();
	sign->Y = BN_new();
}


int verify(struct FwSecSigSign* sign, BIGNUM** m, struct FwSecSigPubKey* pubKey)
{
	BIGNUM* Y = BN_new();
	BIGNUM* c = BN_new();
	BIGNUM* t1 = BN_new();
	BIGNUM* t2 = BN_new();

	// c_i <-- H(..)
	BN_set_word(t1, sign->i);
	hash(c, t1, sign->Y, m[0]);

	// Z^{2^{(T+1)}}
	exp_twos_power(Y, sign->Z, gPubKey->T+1);

	// Y'* PI U^{c_i 2^i}
	BN_one(t2);
	for(int i=0; i<l; i++) {
		if(BN_is_bit_set(c,i)) {
			BN_mod_mul(t1, t2, pubKey->U[i], pubKey->N, ctx);
			BN_copy(t2,t1);
		}
	}
	exp_twos_power(t1, t2, sign->i);

	BN_mod_mul(t2, sign->Y, t1, pubKey->N, ctx);

	int flag = (BN_cmp(Y, t2)==0);

	BN_free(Y);
	BN_free(c);
	BN_free(t1);
	BN_free(t2);

	return flag;
}

int batVerify(struct FwSecSigSign* sign, BIGNUM** m, struct FwSecSigPubKey* pubKey, int theNumber)
{
        BIGNUM* Y = BN_new();
        BIGNUM* V = BN_new();
        BIGNUM* W[l];// = BN_new();
        BIGNUM* Z = BN_new();
        BIGNUM* c = BN_new();
        BIGNUM* t1 = BN_new();
        BIGNUM* t2 = BN_new();

        int i,j;

        // V <-- 1
        BN_set_word(V,1);

	BN_copy(Z,sign->Z);
	BN_one(V);
	for(j=0; j<l; j++) {
		W[j] = BN_new();
        	exp_twos_power(W[j], pubKey->U[j], (pubKey->T - theNumber));

                hash2(c, 0, sign->Y, m[0]);
		if(BN_is_bit_set(c,j)) {
                	BN_mod_mul(V, V, W[j],pubKey->N,ctx);
		}
                BN_mod_mul(V, V, sign->Y, pubKey->N, ctx);
	}

        for(i=0; i<theNumber-1; i++) {
                // Z <-- \prod_{i=1}^{theNumber} Z_i
                BN_mod_mul(Z, Z, sign->Z, pubKey->N, ctx);

                hash2(c, 0, sign->Y, m[0]);
		for(j=0; j<l; j++) {
			BN_mod_mul(W[j],W[j],W[j],pubKey->N,ctx);
			if(BN_is_bit_set(c,j)) {
                		BN_mod_mul(V, V, W[j],pubKey->N,ctx);
			}
		}
                BN_mod_mul(V, V, sign->Y, pubKey->N, ctx);
        }

        // if V==Z^{2^{(T+1)}}
        exp_twos_power(t1, Z, (pubKey->T+1));

        int flag = (BN_cmp(V,t1)==0);

        BN_free(Y);
        BN_free(Z);
        BN_free(V);
        BN_free(c);
        BN_free(t1);
        BN_free(t2);

	for(j=0; j<l; j++)
		BN_free(W[j]);

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
	//sign = malloc(sizeof(struct FwSecSigSign*)*gPubKey->T);
	//message = malloc(sizeof(BIGNUM*)*gPubKey->T);
	sign = malloc(sizeof(struct FwSecSigSign*));
	message = malloc(sizeof(BIGNUM*));

	int i;
	char* tempMsg = malloc(SHA_DIGEST_LENGTH);
	//for(i=0; i<gPubKey->T; i++) {
	for(i=0; i<1; i++) {
		sign[i] = malloc(sizeof(struct FwSecSigSign));
		allocSign(sign[i]);

		message[i] = BN_new();
		
		RAND_bytes(tempMsg, SHA_DIGEST_LENGTH);
		BN_bin2bn(tempMsg, SHA_DIGEST_LENGTH, message[i]);
	}

	start = clock();

	// sign and update
	//for(i=0; i<gPubKey->T; i++) {
	for(i=0; i<1; i++) {
		signMessage(sign[i], message[i]);
	end = clock();
	printf("%f\t", (float)(end-start)/CLOCKS_PER_SEC);

        start = clock();
		update();
	}

	end = clock();
	printf("%f\t", (float)(end-start)/CLOCKS_PER_SEC);


	start = clock();
	// verification for each sign	
//	for(i=0; i<gPubKey->T; i++) {
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

	// size of sign
//	printf("%d\n", BN_num_bytes(sign[0]->Z)+BN_num_bytes(sign[0]->Y)+sizeof(int));

}
