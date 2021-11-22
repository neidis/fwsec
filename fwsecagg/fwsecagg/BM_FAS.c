#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <time.h>
FILE* file;

#define l (SHA_DIGEST_LENGTH*8)

struct FwSecAggSigPartSign {
	BIGNUM* sign;
	BIGNUM* V;
	char h[SHA_DIGEST_LENGTH];
};

struct FwSecAggSigPubKey {
	BIGNUM* U[l];
	int T;
	BIGNUM* N;
}* gPubKey;

struct FwSecAggSigPriKey {
	int i;
	BIGNUM* S[l];
}* gPriKey;

struct FwSecAggSigSessionKey {
	int a;
	int d;
	BIGNUM* v;
	struct FwSecAggSigPartSign* eta;
	BIGNUM* R;
}* gSessionKey;

//struct FwSecAggSigPartSign* gState; 

struct FwSecAggSigSign {
	int a, start, finish;
	BIGNUM* sign;
	struct FwSecAggSigPartSign *eta1, *eta2;
};

int gRSALength;		// k

BN_CTX* ctx;

void allocEta(struct FwSecAggSigPartSign** eta)
{
	*eta = malloc(sizeof(struct FwSecAggSigPartSign));

	(*eta)->sign = BN_new();
	(*eta)->V = BN_new();
}

void initializeStructures()
{
	gPubKey = malloc(sizeof(struct FwSecAggSigPubKey));
	gPriKey = malloc(sizeof(struct FwSecAggSigPriKey));
	gSessionKey = malloc(sizeof(struct FwSecAggSigSessionKey));

	// public key
	gPubKey->N = BN_new();

	// private key
	//gPriKey->v_r = BN_new();

	// session key
	gSessionKey->v = BN_new();
//	allocEta(& gSessionKey->eta);
	gSessionKey->R = BN_new();
	
        for(int i=0; i<l; i++) {
                gPubKey->U[i] = BN_new();

                // private key
                gPriKey->S[i] = BN_new();
        }
}
	

//void hash(BIGNUM* r, int a, BIGNUM* b, BIGNUM* c)
void hash(char* hash_digest, int a, BIGNUM* b, BIGNUM* c)
{
	//char hash_digest[SHA_DIGEST_LENGTH];
	char temp[2048];
	SHA_CTX sha_ctx;
	SHA1_Init(&sha_ctx);

	sprintf(temp, "%x", a);
	SHA1_Update(&sha_ctx, temp, strlen(temp));

	BN_bn2bin(b, temp);
	SHA1_Update(&sha_ctx, temp, BN_num_bytes(b));

	BN_bn2bin(c, temp);
	SHA1_Update(&sha_ctx, temp, BN_num_bytes(c));

	SHA1_Final(hash_digest, &sha_ctx);
	//BN_bin2bn(hash_digest, l/8,r);
}

void copyPartSign(struct FwSecAggSigPartSign* dest, struct FwSecAggSigPartSign* src)
{
	BN_copy(dest->sign, src->sign);
	BN_copy(dest->V, src->V);
	strncpy(dest->h, src->h, l/8);
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

void mul_exp(BIGNUM* sign, BIGNUM* R, BIGNUM** S, char* C)
{
	BN_copy(sign,R);

	int i,j;
	for(i=0; i<l/8; i++) {
		char c = C[i];
		for(j=0; j<8; j++) {	
			if(c & 128) {
				BN_mod_mul(sign, sign, S[8*i+j], gPubKey->N,ctx);
			}
			c <<= 1;
		}
	}
}


// sign
void exp_mul_part(BIGNUM* sign, BIGNUM* r, BIGNUM* x, char* h)
{
        BIGNUM* c = BN_new();
	BN_bin2bn(h, l/8, c);

        BIGNUM* t1 = BN_new();
        BN_mod_exp(sign, x, c, gPubKey->N, ctx);
        BN_mod_mul(sign, sign, r, gPubKey->N, ctx);
}

void hash_exp_mul_part(BIGNUM* sign, BIGNUM* r, BIGNUM* x, BIGNUM* m, BIGNUM* R)
{
        BIGNUM* c = BN_new();
        hash(c, 0, m, R);

        BIGNUM* t1 = BN_new();
        BN_mod_exp(t1, x, c, gPubKey->N, ctx);
        BN_mod_mul(sign, r, t1, gPubKey->N, ctx);

        BN_free(c);
        BN_free(t1);
}

void hash_exp_mul(BIGNUM* sign, BIGNUM* r, BIGNUM** x, int i, BIGNUM* m)
{
	BIGNUM* c= BN_new();
	BIGNUM* t1 = BN_new();
	BIGNUM* t2 = BN_new();
	BN_one(t1);
	BN_one(t2);
	hash(c, i, m, t1);

        for(int i=0; i<l; i++) {
                if(BN_is_bit_set(c,i)) {
                        BN_mod_mul(t1, t2, x[i], gPubKey->N, ctx);
                        BN_copy(t2,t1);
                }
        }

	BN_mod_mul(sign, r, t1, gPubKey->N, ctx);

	BN_free(c);
	BN_free(t1);
	BN_free(t2);
}

// zero knowledge proof
void generatePartialSign(struct FwSecAggSigPartSign *z, BIGNUM* v)
{
	// w <- Z_N
	BIGNUM* w = BN_new();
	BIGNUM* W = BN_new();
	BN_rand_range(w, gPubKey->N);

	// W <-- w^n
	exp_twos_power(W, w, l*(gPubKey->T+1));

	// V <-- v^n
	exp_twos_power(z->V, v, l*(gPubKey->T+1));

	// h <--
	hash(z->h, 0, z->V, W);

	// theta <-- w v^h
	exp_mul_part(z->sign, w, v, z->h);

	BN_free(w);
}
	
int setup()
{
	BIGNUM* t1 = BN_new();
	BIGNUM* t2 = BN_new();
	BIGNUM* t3 = BN_new();

	// key generate
	// p,q <-- Z, N=pq

        // p,q <-- Z, N=pq
        BIGNUM* p = BN_new();
        BIGNUM* q = BN_new();

        while(1) {
                BN_generate_prime_ex(p, gRSALength/2, 0, NULL, NULL, NULL);
                if(BN_is_bit_set(p, 1)) break;
        }

        while(1) {
                BN_generate_prime_ex(q, gRSALength/2, 0, NULL, NULL, NULL);
                if(BN_is_bit_set(q, 1)) break;
        }

        BN_mul(gPubKey->N, p, q, ctx);

        // use phi(N)
        BIGNUM* phi = BN_new();
        BN_sub(t1, p, BN_value_one());
        BN_sub(t2, q, BN_value_one());
        BN_mul(phi,t1, t2,ctx);

        // 2^{(T+1)} mod phi(N)
        BN_set_word(t1, 2);
        BN_set_word(t2, l*(gPubKey->T+1));
        BN_mod_exp(t3, t1, t2, phi,ctx);

	int i;
        for(i=0; i<l; i++) {
                // S_i <-- Z_N
                BN_rand_range(gPriKey->S[i], gPubKey->N);

                // U_i <-- S^{2^{l(T+1)}}
                BN_mod_exp(gPubKey->U[i], gPriKey->S[i], t3, gPubKey->N ,ctx);

		//BN_mod_mul(t1, gPriKey->S[i], gPriKey->S[i], gPubKey->N, ctx);
		exp_twos_power(gPriKey->S[i], gPriKey->S[i], l);
		BN_copy(gPriKey->S[i],t1);
	}

	// i = 1
	gPriKey->i = 1;

	BN_free(t1);
	BN_free(t2);
	BN_free(t3);

	return 0;
}

void init()
{
	BIGNUM* r_j = BN_new();
	BIGNUM* r_j0 = BN_new();

	BN_rand_range(r_j, gPubKey->N);
	BN_rand_range(r_j0, gPubKey->N);
	BN_mod_mul(gSessionKey->v, r_j, r_j0, gPubKey->N, ctx);

 	exp_twos_power(gSessionKey->R, r_j, l*(gPubKey->T+1));
	allocEta(& gSessionKey->eta);
	generatePartialSign(gSessionKey->eta, gSessionKey->v);
	gSessionKey->a = gPriKey->i;
	gSessionKey->d = 0;

	BN_free(r_j);
	BN_free(r_j0);
}

void print_pubkey()
{
	BN_print_fp(file, gPubKey->U);	
	fprintf(file,"\n");

	//BN_print_fp(file, gPubKey->R);	
	//fprintf(file,"\n");

	fprintf(file,"%d\n", gPubKey->T);

//	BN_print_fp(file, gPubKey->u);	
//	fprintf(file,"\n");

	BN_print_fp(file, gPubKey->N);	
	fprintf(file,"\n");

//	BN_print_fp(file, gPubKey->n);	
//	fprintf(file,"\n");
}


void sign_update(struct FwSecAggSigSign* sign, BIGNUM* m)
{
	sign->sign = BN_new();

	char C[l/8];

	// r <-- Z_N
	BIGNUM* r = BN_new();
	BN_rand_range(r, gPubKey->N);

	hash(C, gPriKey->i, m, gSessionKey->R);
	mul_exp(sign->sign, r, gPriKey->S, C); 

	BN_mod_mul(gSessionKey->v, gSessionKey->v, r, gPubKey->N, ctx);

	sign->eta1 = gSessionKey->eta;
	sign->a = gSessionKey->a;
	sign->start = gPriKey->i;
	sign->finish = gPriKey->i;

	// eta update
	allocEta(& gSessionKey->eta);
	generatePartialSign(gSessionKey->eta, gSessionKey->v);
	gSessionKey->d++;
	sign->eta2 = gSessionKey->eta;

	// update secret key
	gPriKey->i ++;

	// S^{2^l}
	int i;
        for(i=0; i<l; i++) {
		//BN_mod_mul(gPriKey->S[i], gPriKey->S[i], gPriKey->S[i], gPubKey->N, ctx);
        	exp_twos_power(gPriKey->S[i], gPriKey->S[i], l);
	}
}

void allocSign(struct FwSecAggSigSign* sign)
{
	sign->sign = BN_new();
/*
	sign->start = BN_new();
	sign->finish = BN_new();
	sign->z_1 = malloc(sizeof(struct FwSecAggSigPartSign));
	sign->z = malloc(sizeof(struct FwSecAggSigPartSign));

	sign->z_1->sign = BN_new();
	sign->z_1->W = BN_new();
	sign->z_1->V = BN_new();

	sign->z->sign = BN_new();
	sign->z->W = BN_new();
	sign->z->V = BN_new();
*/
}

void multi_exp(BIGNUM* y, BIGNUM* x, BIGNUM* u, BIGNUM* index)
{
	// y = x^u^i
	BIGNUM* t1 = BN_new();
	BN_copy(t1,x);

	int n = BN_get_word(index);
	int i;
	for(i=0; i<n; i++) {
		BN_mod_exp(y, t1, u, gPubKey->N, ctx);
		BN_copy(t1, y);
	}

	BN_free(t1);
}

int verifyPartialSign(struct FwSecAggSigPartSign* eta)
{
	BIGNUM* t1= BN_new();
	BIGNUM* t2= BN_new();
	BIGNUM* t3= BN_new();

	char h[l/8];

	exp_twos_power(t1, eta->sign, l*(gPubKey->T+1));
	BN_bin2bn(eta->h, l/8, t3);
	BN_mod_exp(t2, eta->V, t3, gPubKey->N, ctx);	

	BN_mod_inverse(t3, t2, gPubKey->N, ctx);
	BN_mod_mul(t2, t1, t3, gPubKey->N, ctx);

	hash(h, 0, eta->V, t2);

	BN_free(t1);
	BN_free(t2);
	BN_free(t3);

	if(strncmp(h, eta->h, l/8)==0) return 1;
	else return 0;
}

int verify(struct FwSecAggSigSign* sign, BIGNUM** m)
{
	BIGNUM* t1 = BN_new();
	BIGNUM* t2 = BN_new();
	BIGNUM* right = BN_new();
	BIGNUM* left = BN_new();

	// sigma^{2^n} == (V_j/(V_{i-1}^{2^{j-i+1}) U^{u^i c_i }
	// sigma^n * V_{i-1} == V_j R^ ...
	exp_twos_power(t1, sign->sign, l*(gPubKey->T+1));

	BN_mod_mul(left, t1, sign->eta1->V, gPubKey->N, ctx);

	BIGNUM* acc = BN_new();
	BN_one(acc);

	char c[l/8];
	int i;
	for(i=sign->finish; i>=sign->start; --i) {
	//for(i=gPubKey->T; i>=1; --i) {
		//hash(c, i, m[i-sign->start], gSessionKey->R);
		hash(c, 1, m[0], gSessionKey->R);
		mul_exp(t2, acc, gPubKey->U,c);

		// t = t^2
		//BN_mod_mul(acc, t2, t2, gPubKey->N, ctx);
		exp_twos_power(acc,t2,l);
	}

	// acc^{2^{i-1}}
	exp_twos_power(t2, acc, l*(sign->start - 1));

	// V_i * acc
	BN_mod_mul(right, sign->eta2->V, t2, gPubKey->N, ctx);


//	verifyPartialSign(sign->eta1);
//	verifyPartialSign(sign->eta2);

	if(!verifyPartialSign(sign->eta1))
		return 0;

	if(!verifyPartialSign(sign->eta2))
		return 0;

	return BN_cmp(left,right)==0;
}

void aggregate(struct FwSecAggSigSign* agg, struct FwSecAggSigSign* sign1, struct FwSecAggSigSign* sign2)
{
	if(sign1->finish+1 != sign2->start || sign1->a != sign2->a) {
		// error
		return;
	}

	BN_mod_mul(agg->sign, sign1->sign, sign2->sign, gPubKey->N, ctx);
	//copyPartSign(agg->eta1, sign1->eta1);
	//copyPartSign(agg->eta2, sign2->eta2);

	agg->eta1 = sign1->eta1;
	agg->eta2 = sign2->eta2;

	agg->a = sign1->a;
	agg->start = sign1->start;
	agg->finish = sign2->finish;
}

int main(int argc, const char* argv[])
{
	clock_t start, end;
	int numAgg;

	ctx = BN_CTX_new();
//	file = fopen("output.txt","w");


	initializeStructures();

	// argument : rsa_bit_length period_length hash_size
	if(argc < 4) return 0;
	gRSALength = atoi(argv[1]);	// k
	gPubKey->T = atoi(argv[2]);	// T
	numAgg = atoi(argv[3]);	// n

	printf("%d\t", gPubKey->T);
		
	start = clock();
	setup();
	end = clock();
	printf("%f\t", (float)(end-start)/CLOCKS_PER_SEC);

	start = clock();
	init();
	end = clock();
	printf("%f\t", (float)(end-start)/CLOCKS_PER_SEC);

	//print_pubkey();

	// test
	struct FwSecAggSigSign **sign, *aggSign; 
	BIGNUM** message;
	sign = malloc(sizeof(struct FwSecAggSigSign*)*gPubKey->T);
	//message = malloc(sizeof(BIGNUM*)*gPubKey->T);
	//sign = malloc(sizeof(struct FwSecAggSigSign*));
	message = malloc(sizeof(BIGNUM*));

	aggSign = malloc(sizeof(struct FwSecAggSigSign));
	allocSign(aggSign);

	int i;
	char* tempMsg = malloc(SHA_DIGEST_LENGTH);
	for(i=0; i<gPubKey->T; i++) {
	//for(i=0; i<1; i++) {
		sign[i] = malloc(sizeof(struct FwSecAggSigSign));
		allocSign(sign[i]);
	}

	for(i=0; i<2; i++) {
		message[i] = BN_new();
		
		RAND_bytes(tempMsg, SHA_DIGEST_LENGTH);
		BN_bin2bn(tempMsg, SHA_DIGEST_LENGTH, message[i]);
	}

	start = clock();

	// sign and update
	//for(i=0; i<gPubKey->T; i++) {
	for(i=0; i<2; i++) {
		sign_update(sign[i], message[i]);
	}

	end = clock();
	printf("%f\t", (float)(end-start)/CLOCKS_PER_SEC);

	for(i=1; i<gPubKey->T; i++) {
		sign[i]->a = sign[0]->a;
		sign[i]->start = i+1;
		sign[i]->finish = i+1;
		BN_copy(sign[i]->sign,sign[0]->sign);
		sign[i]->eta1 = sign[0]->eta1;
		sign[i]->eta2 = sign[0]->eta2;
	}

	start = clock();
	// verification for each sign	
	//for(i=0; i<gPubKey->T; i++) {
	for(i=0; i<1; i++) {
		if(!verify(sign[i], &message[i])) {
			printf("sign[%d] is invalid\n", i);
		}
	}
	end = clock();
	printf("%f\t", (float)(end-start)/CLOCKS_PER_SEC);
	

	// aggregate

	start = clock();
	aggregate(aggSign, sign[0], sign[1]);
	for(i=2; i<numAgg; i++) {
		aggregate(aggSign, aggSign, sign[i]);
		//aggregate(aggSign, aggSign, sign[0]);
	}
	end = clock();
	printf("%f\t", (float)(end-start)/CLOCKS_PER_SEC);

		
	// aggregate verification
	start = clock();
	if(!verify(aggSign, &message[0])) {
//			printf("aggregate sign is invalid");
	}
	end = clock();
	printf("%f\n", (float)(end-start)/CLOCKS_PER_SEC);

        // size of sign
        //printf("%d\n", BN_num_bytes(sign[0]->sign)+(BN_num_bytes(sign[0]->z->sign)+BN_num_bytes(sign[0]->z->V)+BN_num_bytes(sign[0]->z->W))*2+2*sizeof(int));
}

	
