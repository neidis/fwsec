// Asiacrypto 2000 version

#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <time.h>
FILE* file;

#define l 160

//MSK
struct FwSecMskKey{
	int i;
	int T;
	BIGNUM* N;
	BIGNUM* msk;
};

//VK
struct FwSecSigPubKey {
	int T;
	BIGNUM* U;
	BIGNUM* N;
};

//SK
struct FwSecSigPriKey {
	BIGNUM* N;
	int T;
	BIGNUM* Y;
	BIGNUM* sk;
	int i;
};
//Sign
struct FwSecSigSign{
	BIGNUM* sigma;
	BIGNUM* Y_prime;
	BIGNUM* Y;
};
//ID
struct Identity{
	BIGNUM* Id;
};
// Secret parameter k
int gRSALength;	

BN_CTX* ctx;

// res = HASH1(Y||ID)
void HASH1(BIGNUM* res,BIGNUM* Y,const char* ID){
	char hash_digest[SHA_DIGEST_LENGTH];

	SHA_CTX sha_ctx;
	SHA1_Init(&sha_ctx);

	SHA1_Update(&sha_ctx,ID,strlen(ID));

	BN_bn2bin(Y,ID);
	SHA1_Update(&sha_ctx,ID,BN_num_bytes(Y));

	SHA1_Final(hash_digest,&sha_ctx);

	BN_bin2bn(hash_digest,l/8,res);
}

//res = HASH2(Y||J||M)
void HASH2(BIGNUM* res,BIGNUM* Y_prime,int j,const char* M){
	char hash_digest[SHA_DIGEST_LENGTH];
	char temp[2048];

	sprintf(temp,"%x",j);
	SHA_CTX sha_ctx;
	SHA1_Init(&sha_ctx);

	SHA1_Update(&sha_ctx,M,strlen(M));

	BN_bn2bin(Y_prime,M);
	SHA1_Update(&sha_ctx,M,BN_num_bytes(Y_prime));
	//BN_bn2bin(temp,M);

	SHA1_Update(&sha_ctx,M,strlen(temp));
	SHA1_Final(hash_digest,&sha_ctx);
	BN_bin2bn(hash_digest,l/8,res);
}

// y = x^u^i
void exp_twos_power(BIGNUM* y, BIGNUM* x, int n)
{
	// y = x^u^i
	BIGNUM* t1 = BN_new();
	BN_copy(t1,x);

	int i;
	for(i=0; i<n; i++) {
		BN_mul(y, t1, t1, ctx);
		BN_copy(t1, y);
	}

	BN_free(t1);
}

void setup(struct FwSecMskKey* MSK, struct FwSecSigPubKey* VK,struct Identity* ID)
{
	BIGNUM* temp = BN_new();//U setting tool
	BIGNUM* s = BN_new();//msk setting tool

	BIGNUM* p = BN_new();
    BIGNUM* q = BN_new();
	BIGNUM* tempMSK=BN_new();

	while(1){
		if(BN_generate_prime_ex(p, gRSALength/2, 0, NULL, NULL, NULL))
		{
			printf("p successed!\n");
			break;
		}	
	}
	while(1){
		if(BN_generate_prime_ex(q,gRSALength/2, 0, NULL, NULL, NULL)){
			printf("q successed!\n");
			break;
		}
	}
	//BN_generate_prime_ex(p, gRSALength/2, 0, NULL, NULL, NULL);
	//BN_generate_prime_ex(q, gRSALength/2, 0, NULL, NULL, NULL);

	BN_mul(VK->N, p, q, ctx);//N of VK <-- setting N
	BN_mul(MSK->N,p,q,ctx);// N of MSK <-- setting N


	BN_rand_range(s,VK->N);// s <-- Z_N
	exp_twos_power(tempMSK,s,3*l); // msk_1 of MSK <-- S^2^3l setting 
	BN_mod(MSK->msk,tempMSK,VK->N,ctx);
	exp_twos_power(temp, s, 3*l*(VK->T+1));// t1 <-- S^{2^{3l(T+1)}}
	BN_mod_inverse(VK->U, temp, VK->N, ctx);// U of VK Setting
	
	MSK->i = 1; // i of MSK setting

	BN_rand_range(ID->Id,VK->N);// demo ID : initialize random setting

	BN_free(temp);
	BN_free(s);
	BN_free(p);
    BN_free(q);
}

//KeyIssue(MSK_i , ID) -> SK
void keyIssue(struct FwSecMskKey* MSK, struct Identity* ID,struct FwSecSigPriKey* SK)
{
	BIGNUM* R  = BN_new();
	
	BIGNUM* y = BN_new();
	BIGNUM* Y = BN_new();
	
	BIGNUM* hash1 = BN_new();
	BIGNUM* msk_temp = BN_new();

	SK->N = MSK->N;
	SK->T = MSK->T;
	SK->i = MSK->i;

	BN_rand_range(R,MSK->N);
	exp_twos_power(y,R,3*l*(MSK->T+1-MSK->i));
	BN_mod(Y,y,MSK->N,ctx);
	BN_copy(SK->Y,Y);

	HASH1(hash1,Y,ID->Id);
	BN_exp(msk_temp,MSK->msk,hash1,ctx);
	BN_mod_mul(SK->sk,R,msk_temp,MSK->N,ctx);

	BN_free(R);
	BN_free(Y);
	BN_free(hash1);
	BN_free(msk_temp);
	BN_free(y);
}

void Sign(struct Identity* ID,int j,struct FwSecSigPriKey* SK,const char* M,struct FwSecSigSign* SIGN){
	BIGNUM* R = BN_new(); //R' storage
	BIGNUM* hash2 = BN_new(); // H_2(Y'||j||M) storage 
	BIGNUM* t = BN_new();
	BIGNUM* y = BN_new();

	BN_rand_range(R,SK->N);//setting R'
	exp_twos_power(y,R,3*l*(SK->T+1-j));//setting Y'
	BN_mod(SIGN->Y_prime,y,SK->N,ctx);
	SIGN->Y = SK->Y;
	
	HASH2(hash2,SIGN->Y_prime,j,M);
	BN_exp(t,SK->sk,hash2,ctx);

	BN_mod_mul(SIGN->sigma,R,t,SK->N,ctx);

	BN_free(R);
	BN_free(hash2);
	BN_free(t);
	BN_free(y);
}

void MSKupdate(struct FwSecMskKey* MSK){
	if(MSK->i == MSK->T){
		printf("it is last period!\n");
		return; // 마지막 주기이면 ended
	}
	MSK->i++; // 주기 업데이트;
	
	BIGNUM* next_msk = BN_new();
	exp_twos_power(next_msk,MSK->msk,3*l);
	BN_copy(MSK->msk,next_msk);

	BN_free(next_msk);
}

void UKupdate(struct FwSecSigPriKey* SK){
	SK->i++;
	BIGNUM* next_sk = BN_new();
	exp_twos_power(next_sk,SK->sk,3*l);
	BN_copy(SK->sk,next_sk);

	BN_free(next_sk);
}

void allocSign(struct FwSecSigSign* sign)
{
	sign->sigma = BN_new();
	sign->Y_prime = BN_new();
	sign->Y = BN_new();
}

int verify(struct Identity* ID,const char* M,struct FwSecSigSign* SIGN,struct FwSecSigPubKey* VK,int j){
	BIGNUM* h1 = BN_new();
	BIGNUM* h2 = BN_new();
	BIGNUM* left_hand_side = BN_new();
	BIGNUM* h1h2 = BN_new(); 

	BIGNUM* right_hand_side=BN_new();

	BIGNUM* r0 = BN_new();
	BIGNUM* r1 = BN_new();
	BIGNUM* r2 = BN_new();//Y^h2
	BIGNUM* r3 = BN_new();
	BIGNUM* r4 = BN_new();// (1/U)^h1h2

	HASH1(h1,SIGN->Y,ID->Id);
	HASH2(h2,SIGN->Y_prime,j,M);

	exp_twos_power(r0,SIGN->sigma,3*l*(VK->T+1-j));
	
	BN_mul(h1h2,h1,h2,ctx);
	BN_exp(r2, SIGN->Y, h2, ctx); // Y^h2
	BN_mul(r3,VK->U,h1h2,ctx);
	BN_mod_inverse(r4, r3,VK->N, ctx);// (1/U)^h1h2 of VK Setting
	BN_mul(r1,r2,r4,ctx);

	BN_mod_mul(right_hand_side,SIGN->Y_prime,r1,VK->N,ctx);
	BN_mod(left_hand_side,r0,VK->N,ctx);

	int flag = BN_cmp(left_hand_side,right_hand_side);

	BN_free(h1);
	BN_free(h2);
	BN_free(left_hand_side);
	BN_free(h1h2);
	BN_free(right_hand_side);
	BN_free(r0);
	BN_free(r1);
	BN_free(r2);
	BN_free(r3);
	BN_free(r4);

	return flag;
}

int main(int argc, const char* argv[])
{
	ctx = BN_CTX_new();
	const char* message = "A";
	const char* message2 = "B";
	struct FwSecMskKey *MSK = malloc(sizeof(struct FwSecMskKey));
	struct FwSecSigPubKey *VK = malloc(sizeof(struct FwSecSigPubKey));
	struct Identity *ID = malloc(sizeof(struct Identity));
	//public key
	VK->U = BN_new();
	VK->N = BN_new();

	//msk private key
	MSK->N = BN_new();
	MSK->msk = BN_new();
	ID->Id = BN_new();

	//argument : rsa_bit_length period_length
	if(argc < 3){
		printf("argument : k T is needed\n");
		return 0;
	} 
	gRSALength = atoi(argv[1]);	// k
	VK->T = atoi(argv[2]);	// setting T
	VK->T = atoi(argv[2]); // setting T

	printf("setup start\n");
	setup(MSK,VK,ID);
	printf("setup ended\n");
	
	// initialize SK
	struct FwSecSigPriKey *SK = malloc(sizeof(struct FwSecSigPriKey));
	SK->N = BN_new();
	SK->Y = BN_new();
	SK->sk = BN_new();
	printf("keyIssue start\n");
	keyIssue(MSK,ID,SK);
	printf("keyIssue ended\n");

	struct FwSecSigSign *SIGN = malloc(sizeof(struct FwSecSigSign));
	//struct FwSecSigSign **SIGN = malloc(sizeof(struct FwSecSigSign*));
	allocSign(SIGN);
	printf("Sign start\n");
	Sign(ID,0,SK,message,SIGN);
	printf("Sign ended\n");

	int flag;
	printf("Verify start\n");
	flag = verify(ID,"sdfjdsalkfjlsk",SIGN,VK,0);
	printf("verify ended\n");

	printf("Value of flag => %d\n",flag);
	
	return 0;
}

