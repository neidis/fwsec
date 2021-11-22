#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <time.h>
FILE* file;

#define l 160

struct FwSecAggSigPartSign {
	BIGNUM* sign;
	BIGNUM* V;
	BIGNUM* W;
};

struct FwSecAggSigPubKey {
	BIGNUM* Y[l];
//	BIGNUM* R;
	int T;
	BIGNUM* N;
	int n;
}* gPubKey;

struct FwSecAggSigPriKey {
	int i;
	BIGNUM* x[l];
//	BIGNUM* r;
	BIGNUM* v_r;
}* gPriKey;

struct FwSecAggSigPartSign* gState; 

struct FwSecAggSigSign {
	BIGNUM* sign;
	struct FwSecAggSigPartSign *z_1, *z;

	int start;
	int finish;
};

int gRSALength;		// k

BN_CTX* ctx;

void initializeStructures()
{
	// public key
	gPubKey->N = BN_new();
	//gPubKey->R = BN_new();

	// private key
	//gPriKey->r = BN_new();
	gPriKey->v_r = BN_new();

	// state
	gState->sign = BN_new();
	gState->V = BN_new();
	gState->W = BN_new();

        for(int i=0; i<l; i++) {
                gPubKey->Y[i] = BN_new();

                // private key
                gPriKey->x[i] = BN_new();
        }
}
	

void hash(BIGNUM* r, int a, BIGNUM* b, BIGNUM* c)
{
	char hash_digest[SHA_DIGEST_LENGTH];
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
	BN_bin2bn(hash_digest, l/8,r);
}

void copyPartSign(struct FwSecAggSigPartSign* dest, struct FwSecAggSigPartSign* src)
{
	BN_copy(dest->sign, src->sign);
	BN_copy(dest->V, src->V);
	BN_copy(dest->W, src->W);
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


// sign
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
	BN_rand_range(w, gPubKey->N);

	// W <-- w^n
	exp_twos_power(z->W, w, gPubKey->n);

	// V <-- v^n
	exp_twos_power(z->V, v, gPubKey->n);

	// theta <-- w v^H(i || V || W)
	hash_exp_mul_part(z->sign, w, v, z->V, z->W);

	BN_free(w);
}
	
int setup()
{
	BIGNUM* t1 = BN_new();

	// key generate
	RSA* rsa;

	// p,q <-- Z, N=pq
	rsa = RSA_generate_key(gRSALength, 5, NULL, NULL);
        if(RSA_check_key(rsa) != 1) {
               perror("not gnerate RSA key");
               exit(0);
	}

	BN_copy(gPubKey->N,rsa->n);

	// n = T+1
	gPubKey->n =  gPubKey->T+1;

	// pick random x0, r0, u <-- Z_N
	int i;
        for(i=0; i<l; i++) {

                // x_0[i] <-- Z_N
		while(1) {
                	BN_rand_range(gPriKey->x[i], gPubKey->N);
			BN_gcd(t1, gPriKey->x[i],gPubKey->N, ctx);
			if(BN_is_one(t1)) break;
		}
		//BN_rand_range(gPriKey->x, gPubKey->N);

                // Y[i] <-- S^{2^n}
		exp_twos_power(gPubKey->Y[i], gPriKey->x[i], gPubKey->n);

		//if(BN_is_zero(gPubKey->Y[i]))
		//	printf("%d is zero\n", i);
        }

        for(i=0; i<l; i++) {
		BN_mod_mul(t1, gPriKey->x[i], gPriKey->x[i], gPubKey->N, ctx);
		BN_copy(gPriKey->x[i],t1);
	}

	//BN_rand_range(gPriKey->r, gPubKey->N);
	//exp_twos_power(gPubKey->R, gPriKey->r, gPubKey->n);

	BIGNUM* v = BN_new();
	BN_rand_range(v, gPubKey->N);

	generatePartialSign(gState, v);

	// v_0^2
	BN_mod_mul(gPriKey->v_r, v, v, gPubKey->N, ctx);

	// i = 1
	gPriKey->i = 1;

	BN_free(t1);
	RSA_free(rsa);

	return 0;
}

void print_pubkey()
{
	BN_print_fp(file, gPubKey->Y);	
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
	// z_{i-1} <-- z_i
	copyPartSign(sign->z_1, gState);
	
	BIGNUM* t1 = BN_new();
	BIGNUM* t2 = BN_new();
	BIGNUM* t3 = BN_new();
	BIGNUM* t4 = BN_new();

	// r <-- Z_N
	BIGNUM* r = BN_new();
	BN_rand_range(r, gPubKey->N);

	// v_i <-- (v_r) r_i 
	BIGNUM* v = BN_new();
	BN_mod_mul(v, gPriKey->v_r, r, gPubKey->N, ctx);

	// sigma <--
	hash_exp_mul(sign->sign, r, gPriKey->x, gPriKey->i, m);

	// start = finish = i
	sign->start = gPriKey->i;
	sign->finish = gPriKey->i;

	// z_i <--
	generatePartialSign(sign->z, v);

	// state update
	copyPartSign(gState, sign->z);

	// update secret key
	// i++
	gPriKey->i ++;

	// x^2
	int i;
        for(i=0; i<l; i++) {
		BN_mod_mul(t1, gPriKey->x[i], gPriKey->x[i], gPubKey->N, ctx);
		BN_copy(gPriKey->x[i], t1);
	}

	// v_r <-- (v_i)^2
	BN_mod_mul(gPriKey->v_r, v, v, gPubKey->N, ctx);
}


void allocSign(struct FwSecAggSigSign* sign)
{
	sign->sign = BN_new();
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

int verifyPartialSign(struct FwSecAggSigPartSign* sign, int index, struct FwSecAggSigPubKey* pubKey)
{
	BIGNUM* t1= BN_new();
	hash_exp_mul_part(t1, sign->W, sign->V, sign->V, sign->W);

	BIGNUM* t2= BN_new();
	exp_twos_power(t2, sign->sign, pubKey->n);

	return BN_cmp(t1,t2)==0;
}

int verify(struct FwSecAggSigSign* sign, BIGNUM** m, struct FwSecAggSigPubKey* pubKey)
{
	BIGNUM* t1 = BN_new();
	BIGNUM* t2 = BN_new();
	BIGNUM* right = BN_new();
	BIGNUM* left = BN_new();

	// sigma^{2^n} == (V_j/(V_{i-1}^{2^{j-i+1}) Y^{u^i c_i }
	// sigma^n * V_{i-1} == V_j R^ ...
	exp_twos_power(t1, sign->sign, pubKey->n);

	// V_{i-1}^{2^{j-i+1}}
	exp_twos_power(t2, sign->z_1->V, sign->finish - sign->start + 1);

	BN_mod_mul(left, t1, t2, pubKey->N, ctx);

	//  (RY^Hi (RY^{H_{i+1})^2 ... (RY^H_{j-i+1})^{2^{j-i})^2^{i} 
	BIGNUM* acc = BN_new();
	BN_one(acc);

	int i;
	for(i=sign->finish; i>=sign->start; --i) {
		// t = R*Y^H(...)
		hash_exp_mul(t2, acc, pubKey->Y, i, m[i - sign->start]);
		// t = t^2
		BN_mod_mul(acc, t2, t2, pubKey->N, ctx);
	}

	// acc^{2^{i-1}}
	exp_twos_power(t2, acc, sign->start - 1);

	// V_i * acc
	BN_mod_mul(right, sign->z->V, t2, pubKey->N, ctx);

	if(!verifyPartialSign(sign->z_1, sign->start - 1, pubKey))
		return 0;

	if(!verifyPartialSign(sign->z, sign->finish, pubKey))
		return 0;

	return BN_cmp(left,right)==0;
}

void aggregate(struct FwSecAggSigSign* agg, struct FwSecAggSigSign* sign1, struct FwSecAggSigSign* sign2)
{
	if(sign1->finish+1 != sign2->start) {
		// error
		return;
	}

	BN_mod_mul(agg->sign, sign1->sign, sign2->sign, gPubKey->N, ctx);
	copyPartSign(agg->z_1, sign1->z_1);
	copyPartSign(agg->z, sign2->z);

	agg->start = sign1->start;
	agg->finish = sign2->finish;
}

int main(int argc, const char* argv[])
{
	clock_t start, end;

	ctx = BN_CTX_new();
//	file = fopen("output.txt","w");

	gPubKey = malloc(sizeof(struct FwSecAggSigPubKey));
	gPriKey = malloc(sizeof(struct FwSecAggSigPriKey));
	gState = malloc(sizeof(struct FwSecAggSigPartSign));

	initializeStructures();

	// argument : rsa_bit_length period_length hash_size
	if(argc < 3) return 0;
	gRSALength = atoi(argv[1]);	// k
	gPubKey->T = atoi(argv[2]);	// T

	printf("%d\t", gPubKey->T);
		
	start = clock();
	setup();
	end = clock();
	printf("%f\t", (float)(end-start)/CLOCKS_PER_SEC);

	//print_pubkey();

	// test
	struct FwSecAggSigSign **sign, *aggSign; 
	BIGNUM** message;
	sign = malloc(sizeof(struct FwSecAggSigSign*)*gPubKey->T);
	message = malloc(sizeof(BIGNUM*)*gPubKey->T);

	aggSign = malloc(sizeof(struct FwSecAggSigSign));
	allocSign(aggSign);

	int i;
	char* tempMsg = malloc(SHA_DIGEST_LENGTH);
	for(i=0; i<gPubKey->T; i++) {
		sign[i] = malloc(sizeof(struct FwSecAggSigSign));
		allocSign(sign[i]);

		message[i] = BN_new();
		
		RAND_bytes(tempMsg, SHA_DIGEST_LENGTH);
		BN_bin2bn(tempMsg, SHA_DIGEST_LENGTH, message[i]);
	}

	start = clock();

	// sign and update
	for(i=0; i<gPubKey->T; i++) {
		sign_update(sign[i], message[i]);
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
	

	// aggregate
	start = clock();
	aggregate(aggSign, sign[0], sign[1]);
	for(i=2; i<gPubKey->T; i++) {
		aggregate(aggSign, aggSign, sign[i]);
	}
	end = clock();
	printf("%f\t", (float)(end-start)/CLOCKS_PER_SEC);
		
	// aggregate verification
	start = clock();
	if(!verify(aggSign, &message[0], gPubKey)) {
			printf("aggregate sign is invalid");
	}
	end = clock();
	printf("%f\t", (float)(end-start)/CLOCKS_PER_SEC);

        // size of sign
        printf("%d\n", BN_num_bytes(sign[0]->sign)+(BN_num_bytes(sign[0]->z->sign)+BN_num_bytes(sign[0]->z->V)+BN_num_bytes(sign[0]->z->W))*2+2*sizeof(int));
}

	
