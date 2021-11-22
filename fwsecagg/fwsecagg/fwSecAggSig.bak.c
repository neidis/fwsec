#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <time.h>
FILE* file;

struct FwSecAggSigPartSign {
	BIGNUM* sign;
	BIGNUM* W;
	BIGNUM* V;
};

struct FwSecAggSigPubKey {
	BIGNUM* Y;
	BIGNUM* R;
	int T;
	BIGNUM* u;
	BIGNUM* N;
	BIGNUM* n;
}* gPubKey;

struct FwSecAggSigPriKey {
	int i;
	BIGNUM* x;
	BIGNUM* r;
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
	gPubKey->u = BN_new();
	gPubKey->n = BN_new();
	gPubKey->Y = BN_new();
	gPubKey->R = BN_new();

	// private key
	gPriKey->x = BN_new();
	gPriKey->r = BN_new();
	gPriKey->v_r = BN_new();

	// state
	gState->sign = BN_new();
	gState->V = BN_new();
	gState->W = BN_new();
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

	BN_bin2bn(hash_digest, SHA_DIGEST_LENGTH, r);
}

void copyPartSign(struct FwSecAggSigPartSign* dest, struct FwSecAggSigPartSign* src)
{
	BN_copy(dest->sign, src->sign);
	BN_copy(dest->V, src->V);
	BN_copy(dest->W, src->W);
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

// zero knowledge proof
void generatePartialSign(struct FwSecAggSigPartSign *z, BIGNUM* v, BIGNUM* i)
{
	// w <- Z_N
	BIGNUM* w = BN_new();
	BN_rand_range(w, gPubKey->N);

	// W <-- w^n
	BN_mod_exp(z->W, w, gPubKey->n, gPubKey->N, ctx);

	// V <-- v^n
	BN_mod_exp(z->V, v, gPubKey->n, gPubKey->N, ctx);

	// theta <-- w v^H(i || V || W)
	hash_exp_mul(z->sign, w, v, i, z->V, z->W);

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

	// pick random x0, r0, u <-- Z_N
	BN_rand_range(gPriKey->x, gPubKey->N);
	BN_rand_range(gPriKey->r, gPubKey->N);
	BN_copy(gPubKey->u,rsa->e);

	// pick n <-- Z_phi(N)
//	BN_rand_range(gPubKey->n, gPubKey->N);
	BN_set_word(gPubKey->n, 7);

	BN_mod_exp(gPubKey->Y, gPriKey->x, gPubKey->n, gPubKey->N, ctx);
	BN_mod_exp(gPubKey->R, gPriKey->r, gPubKey->n, gPubKey->N, ctx);

	gPriKey->i = 0;

	BIGNUM* v = BN_new();
	BN_rand_range(v, gPubKey->N);

	BN_set_word(t1, gPriKey->i);
	generatePartialSign(gState, v, t1);

	// key update (generate SK_1)
	// x^u
	BN_mod_exp(t1, gPriKey->x, gPubKey->u, gPubKey->N, ctx);
	BN_copy(gPriKey->x, t1);

	// r^u 
	BN_mod_exp(t1, gPriKey->r, gPubKey->u, gPubKey->N, ctx);
	BN_copy(gPriKey->r, t1);

	// v_0/r^u
	BN_mod_inverse(t1, gPriKey->r, gPubKey->N, ctx);
	BN_mod_mul(gPriKey->v_r, v, t1, gPubKey->N, ctx);

	// r^u^2
	BN_mod_exp(t1, gPriKey->r, gPubKey->u, gPubKey->N, ctx);
	BN_copy(gPriKey->r, t1);

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

	BN_print_fp(file, gPubKey->R);	
	fprintf(file,"\n");

	fprintf(file,"%d\n", gPubKey->T);

	BN_print_fp(file, gPubKey->u);	
	fprintf(file,"\n");

	BN_print_fp(file, gPubKey->N);	
	fprintf(file,"\n");

	BN_print_fp(file, gPubKey->n);	
	fprintf(file,"\n");
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

/*
	//debug
	BN_mod_inverse(t1, gPriKey->v_r, gPubKey->N,ctx);
	BN_mod_mul(t2, v, t1, gPubKey->N,ctx);
	fprintf(file,"pre v/vi-1 r^ui= ");
	BN_print_fp(file, t2);	
	fprintf(file,"\n");
*/
	
	// sigma <--
	BN_set_word(t1, gPriKey->i);
	hash_exp_mul(sign->sign, r, gPriKey->x, t1, m, gPubKey->R);

	// debug
/*
	BN_mod_exp(t2, sign->sign, gPubKey->n, gPubKey->N, ctx);
	fprintf(file,"t2 (sign) = ");
	BN_print_fp(file, t2);
	fprintf(file,"\n");

	fprintf(file,"sign (sign)= ");
	BN_print_fp(file, sign->sign);	
	fprintf(file,"\n");
*/

	// start = finish = i
	sign->start = gPriKey->i;
	sign->finish = gPriKey->i;

	// z_i <--
	generatePartialSign(sign->z, v, t1);

	// state update
	copyPartSign(gState, sign->z);

/*
	// debug
	fprintf(file,"state = ");
	BN_print_fp(file, gState->V);
	fprintf(file,"\n");

	BIGNUM* v_temp = BN_new();
	BN_copy(v_temp, gPriKey->v_r);
	sign->ri = BN_new();
	BN_copy(sign->ri, r);
*/

	// update secret key
	// i++
	gPriKey->i ++;

	// x^u
	BN_mod_exp(t1, gPriKey->x, gPubKey->u, gPubKey->N, ctx);
	BN_copy(gPriKey->x, t1);

	// v_r <-- v_i / r_i^u
	BN_mod_inverse(t1, gPriKey->r, gPubKey->N, ctx);
	BN_mod_mul(gPriKey->v_r, v, t1, gPubKey->N, ctx);

	// r_(i+1) <-- r_i^u
	BN_mod_exp(t1, gPriKey->r, gPubKey->u, gPubKey->N, ctx);
	BN_copy(gPriKey->r, t1);
	//debug
/*
	BN_mod_exp(t1, gPriKey->r, gPubKey->n, gPubKey->N, ctx);
	fprintf(file,"(r^u^i)^n= ...");
	BN_print_fp(file, t1);
	fprintf(file,"\n");
*/


	// debug
/*
	fprintf(file,"sign->ri= ");
	BN_print_fp(file, sign->ri);
	fprintf(file,"\n");
	fprintf(file,"ri= ");
	BN_print_fp(file, r);
	fprintf(file,"\n");
	BN_mod_inverse(t1, v_temp, gPubKey->N,ctx);
	BN_mod_mul(t2, v, t1, gPubKey->N,ctx);
	fprintf(file,"post v/vi-1 r^ui= ");
	BN_print_fp(file, t2);	
	fprintf(file,"\n");
	fprintf(file,"Vi-1= ");
	BN_print_fp(file, sign->z_1->V);
	fprintf(file,"\n");
	fprintf(file,"Vi= ");
	BN_print_fp(file, sign->z->V);
	fprintf(file,"\n");
	fprintf(file,"vi= ");
	BN_print_fp(file, v);
	fprintf(file,"\n");
	BN_copy(t1,gPubKey->R);
	for(int i=1; i< gPriKey->i; i++) {
		BN_mod_exp(t2, t1, gPubKey->u, gPubKey->N,ctx);
		BN_copy(t1,t2);
	}
	BN_copy(t4,t1);
	BN_mod_mul(t2, t1, sign->z->V, gPubKey->N,ctx);
	BN_mod_inverse(t1, sign->z_1->V, gPubKey->N, ctx);
	BN_mod_mul(t3, t1, t2, gPubKey->N,ctx);
	fprintf(file,"Vi/Vi-1 R^u^i= ");
	BN_print_fp(file, t3);
	fprintf(file,"\n");
	BN_mod_exp(t1, sign->ri, gPubKey->n, gPubKey->N, ctx); 
	fprintf(file,"ri^n= ");
	BN_print_fp(file, t1);
	fprintf(file,"\n");
	BN_mod_exp(t1, v_temp, gPubKey->n, gPubKey->N,ctx);
	BN_mod_inverse(t2, t1, gPubKey->N, ctx);
	BN_mod_mul(t1, sign->z->V, t2, gPubKey->N,ctx);
	fprintf(file,"Vi/(v_r)^n= ");
	BN_print_fp(file, t1);
	fprintf(file,"\n");
	BN_mod_exp(t1, v_temp, gPubKey->n, gPubKey->N,ctx);
	fprintf(file,"(v_r)^n= ");
	BN_print_fp(file, t1);
	fprintf(file,"\n");
	BN_mod_inverse(t1, t4, gPubKey->N, ctx);
	BN_mod_mul(t2, sign->z_1->V, t1, gPubKey->N,ctx);
	fprintf(file,"Vi-1/R^u^i= ");
	BN_print_fp(file, t2);
	fprintf(file,"\n");
	fprintf(file,"R^u^i= ");
	BN_print_fp(file, t4);
	fprintf(file,"\n");
	BN_mod_exp(t2, t4, gPubKey->u, gPubKey->N, ctx);
	//BN_mod_exp(t1, t2, gPubKey->u, gPubKey->N, ctx);
	fprintf(file,"R^u^(i+2)= ");
	BN_print_fp(file, t2);
	fprintf(file,"\n");
	BN_mod_exp(t1, gPriKey->r, gPubKey->n, gPubKey->N, ctx);
	fprintf(file,"r^(nu^(i+2)= ");
	BN_print_fp(file, t1);
	fprintf(file,"\n");
	BN_copy(t1,gPubKey->R);
	fprintf(file,"R= ");
	BN_print_fp(file, t1);
	fprintf(file,"\n");
	BN_mod_exp(t2,t1, gPubKey->u, gPubKey->N, ctx);
	fprintf(file,"R^u= ");
	BN_print_fp(file, t2);
	fprintf(file,"\n");
	BN_mod_exp(t1,t2, gPubKey->u, gPubKey->N, ctx);
	fprintf(file,"R^u^2= ");
	BN_print_fp(file, t1);
	fprintf(file,"\n");
	BN_mod_exp(t2,t1, gPubKey->u, gPubKey->N, ctx);
	fprintf(file,"R^u^3= ");
	BN_print_fp(file, t2);
	fprintf(file,"\n");
	BN_mod_exp(t1,t2, gPubKey->u, gPubKey->N, ctx);
	fprintf(file,"R^u^4= ");
	BN_print_fp(file, t1);
	fprintf(file,"\n");
	BN_mod_exp(t2,t1, gPubKey->u, gPubKey->N, ctx);
	fprintf(file,"R^u^5= ");
	BN_print_fp(file, t2);
	fprintf(file,"\n");
	BN_mod_exp(t1,t2, gPubKey->u, gPubKey->N, ctx);
	fprintf(file,"R^u^6= ");
	BN_print_fp(file, t1);
	fprintf(file,"\n");
*/

	
	
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

int verifyPartialSign(struct FwSecAggSigPartSign* sign, BIGNUM* index, struct FwSecAggSigPubKey* pubKey)
{
	BIGNUM* t1= BN_new();
	hash_exp_mul(t1, sign->W, sign->V, index , sign->V, sign->W);

	BIGNUM* t2= BN_new();
	BN_mod_exp(t2, sign->sign, pubKey->n, pubKey->N, ctx);

	return BN_cmp(t1,t2)==0;
}

int verify(struct FwSecAggSigSign* sign, BIGNUM** m, struct FwSecAggSigPubKey* pubKey)
{
	BIGNUM* t1 = BN_new();
	BIGNUM* t2 = BN_new();
	BIGNUM* index = BN_new();
	BIGNUM* right = BN_new();
	BIGNUM* left = BN_new();

/*
	fprintf(file,"z_1->V = ");
	BN_print_fp(file, sign->z_1->V);
	fprintf(file,"\n");

	fprintf(file,"sign (veri) = ");
	BN_print_fp(file, sign->sign);	
	fprintf(file,"\n");
*/

	// sigma^n == (V_j/(V_{i-1}) R^{u^i} Y^{u^i c_i }
	// sigma^n * V_{i-1} == V_j R^ ...
	BN_mod_exp(t1, sign->sign, pubKey->n, pubKey->N, ctx);

	BN_mod_mul(left, t1, sign->z_1->V, pubKey->N, ctx);

	//  (RY^Hi (RY^H_{i+1})^u ... (RY^H_{j-i+1})^{j-i})^u^{i} 
	BIGNUM* R = BN_new();
	BIGNUM* Y = BN_new();
	BN_copy(R, pubKey->R);

	BN_copy(Y, pubKey->Y);

	BIGNUM* acc = BN_new();
	BN_one(acc);

	int i;
	for(i=sign->start; i<=sign->finish; i++) {
		BN_set_word(index, i);
		hash_exp_mul(t1, R, Y, index, m[i - sign->start], pubKey->R);

		BN_mod_mul(t2, acc, t1, pubKey->N, ctx);
		BN_copy(acc, t2);

		BN_mod_exp(t2, R, pubKey->u, pubKey->N, ctx);
		BN_copy(R, t2); 
		BN_mod_exp(t2, Y, pubKey->u, pubKey->N, ctx);
		BN_copy(Y, t2); 
	}


	// acc^u^i
	BN_set_word(index, sign->start);
	multi_exp(t2, acc, pubKey->u, index);
/*
	fprintf(file,"t2 (veri) = ");
	BN_print_fp(file, t2);
	fprintf(file,"\n");
*/

	// V_i * acc
	BN_mod_mul(right, sign->z->V, t2, pubKey->N, ctx);

	// debug
/*
	BN_mod_exp(t1, sign->ri, pubKey->n, pubKey->N, ctx);
	fprintf(file,"ri^n = ");
	BN_print_fp(file, t1);
	fprintf(file,"\n");
	BN_mod_exp(t2, pubKey->R, pubKey->u, pubKey->N, ctx);
	BN_mod_exp(t1, t2, pubKey->u, pubKey->N, ctx);
	BN_mod_mul(t2, t1, sign->z->V, pubKey->N, ctx);
	BN_mod_inverse(t1, sign->z_1->V, pubKey->N, ctx);
	BN_mod_mul(right, t2, t1, pubKey->N, ctx);
	fprintf(file,"Vi/Vi-1 R^u^2 = ");
	BN_print_fp(file, right);
	fprintf(file,"\n");
	fprintf(file,"Vi = ");
	BN_print_fp(file, sign->z->V);
	fprintf(file,"\n");
	fprintf(file,"Vi-1 = ");
	BN_print_fp(file, sign->z_1->V);
	fprintf(file,"\n");
	fprintf(file,"R = ");
	BN_print_fp(file, pubKey->R);
	fprintf(file,"\n");
	fprintf(file,"u = ");
	BN_print_fp(file, pubKey->u);
	fprintf(file,"\n");
	fprintf(file,"ri = ");
	BN_print_fp(file, sign->ri);
	fprintf(file,"\n");

	fprintf(file,"left = ");
	BN_print_fp(file, left);
	fprintf(file,"\n");
	fprintf(file,"right = ");
	BN_print_fp(file, right);
	fprintf(file,"\n");
	printf("cmp : %d\n", BN_cmp(left,right));
*/

	BN_set_word(t1, sign->start-1);
	if(!verifyPartialSign(sign->z_1, t1, pubKey))
		return 0;

	BN_set_word(t1, sign->finish);
	if(!verifyPartialSign(sign->z, t1, pubKey))
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
	//file = fopen("output.txt","w");

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

	
