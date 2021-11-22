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

//ret = base^(2^n)
void power_function(BIGNUM* ret ,BIGNUM* base , int n,BIGNUM* N){
	BIGNUM* two = BN_new();
	BIGNUM* expo =BN_new();
	BN_add(two,BN_value_one(),BN_value_one());//t is 2
	BN_copy(expo,two);// initialize ret is 2
	int i;
	
	for(i=1;i<n;i++){
		BN_mul(expo,expo,two,ctx);
	}

	BN_mod_exp(ret,base,expo,N,ctx);
	printf("ret : ");
	BN_print_fp(stdout,ret);
	printf("\n");
	BN_free(expo);
	BN_free(two);
}

void setup(struct FwSecMskKey* MSK, struct FwSecSigPubKey* VK,struct Identity* ID)
{
	BIGNUM* temp = BN_new();//U setting tool
	BIGNUM* s = BN_new();//msk setting tool

	BIGNUM* p = BN_new();
    BIGNUM* q = BN_new();
//	BIGNUM* tempMSK=BN_new();

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
//	BN_mul(MSK->N,p,q,ctx);// N of MSK <-- setting N
	BN_copy(MSK->N, VK->N);								//hankyung modified


	BN_rand_range(s,VK->N);// s <-- Z_N
//	exp_twos_power(tempMSK,s,3*l); // msk_1 of MSK <-- S^2^3l setting 


	//hankyung modified
	// msk_1 of MSK <-- S^2^3l setting
	BIGNUM* phiN = BN_new();
	BIGNUM* p1 = BN_new();
	BIGNUM* q1 = BN_new();
	BN_sub(p1, p, BN_value_one());	// p1 = p - 1
	BN_sub(q1, q, BN_value_one());	// q1 = q - 1
	BN_mul(phiN, p1, q1, ctx);		// phiN = (p - 1)(q - 1)
	BIGNUM* bnL = BN_new();
	BIGNUM* bn3L = BN_new();
	BN_dec2bn(&bnL, "160");			// edit "160" into argv[3] later....
	BN_add(bn3L, bnL, bnL);
	BN_add(bn3L, bn3L, bnL);		// bn3L = l * 3
	BIGNUM* bntwo = BN_new();	
	BN_add(bntwo, BN_value_one(), BN_value_one());	// bntwo = 2
	BN_mod_exp(temp, bntwo, bn3L, phiN, ctx);		// temp = 2 ^ 3l mod phiN
	BN_mod_exp(MSK->msk, s, temp, VK->N, ctx);		// msk = s ^ temp mod N
	printf("msk_1 : ");
	BN_print_fp(stdout, MSK->msk);
	printf("\n");
	// end of setting msk_1
	


//	BN_mod(MSK->msk,tempMSK,VK->N,ctx);
//	exp_twos_power(temp, s, 3*l*(VK->T+1));// t1 <-- S^{2^{3l(T+1)}}
//	BN_mod_inverse(VK->U, temp, VK->N, ctx);// U of VK Setting
	
	//hankyung modified
	// U of VK setting
	BIGNUM* bnT = BN_new();
	BN_dec2bn(&bnT, "2048");							//edit "2048" into argv[2] later...
	BN_add(bnT, bnT, BN_value_one());					// bnT = T + 1
	BN_mod_exp(VK->U, MSK->msk, bnT, VK->N, ctx);		
	BN_mod_inverse(VK->U, VK->U, VK->N, ctx);
	printf("U : ");
	BN_print_fp(stdout, VK->U);
	printf("\n");
	// end of setting U

	MSK->i = 1; // i of MSK setting

	BN_rand_range(ID->Id,VK->N);// demo ID : initialize random setting
	printf("ID : ");
	BN_print_fp(stdout, ID->Id);
	printf("\n");

	BN_free(temp);
	BN_free(s);
	BN_free(p);
    BN_free(q);
	BN_free(phiN);
	BN_free(p1);
	BN_free(q1);
	BN_free(bnL);
	BN_free(bn3L);
	BN_free(bntwo);
	BN_free(bnT);
}

//KeyIssue(MSK_i , ID) -> SK
void keyIssue(struct FwSecMskKey* MSK, struct Identity* ID,struct FwSecSigPriKey* SK)
{
	BIGNUM* R  = BN_new();
	BIGNUM* Y = BN_new();
	BIGNUM* hash1 = BN_new();
	BIGNUM* msk_temp = BN_new();
	
	printf("N of MSK : ");
	BN_print_fp(stdout, MSK->N);
	printf("\n");
	printf("T of MSK : %d\n",MSK->T);
	printf("i of MSK : %d\n",MSK->i);
	
	BN_copy(SK->N,MSK->N);
	SK->T = MSK->T;
	SK->i = MSK->i;

	BN_rand_range(R,MSK->N);
	printf("R : ");
	BN_print_fp(stdout,R);
	printf("\n");
	power_function(Y,R,3*l*(MSK->T+1-MSK->i),MSK->N);
	BN_copy(SK->Y,Y);
	printf("Y of SK : ");
	BN_print_fp(stdout,Y);


	HASH1(hash1,Y,ID->Id);
	BN_exp(msk_temp,MSK->msk,hash1,ctx);
	BN_mod_mul(SK->sk,R,msk_temp,MSK->N,ctx);
		
	BN_free(R);
	BN_free(Y);
	BN_free(hash1);
	BN_free(msk_temp);
}

void Sign(struct Identity* ID,int j,struct FwSecSigPriKey* SK,const char* M,struct FwSecSigSign* SIGN){
	BIGNUM* R = BN_new(); //R' storage
	BIGNUM* hash2 = BN_new(); // H_2(Y'||j||M) storage 
	BIGNUM* t = BN_new();
	BIGNUM* y = BN_new();

	BN_rand_range(R,SK->N);//setting R'
	power_function(SIGN->Y_prime,R,3*l*(SK->T+1-j),SK->N);
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
	power_function(next_msk,MSK->msk,3*l,MSK->N);
	BN_copy(MSK->msk,next_msk);

	BN_free(next_msk);
}

void UKupdate(struct FwSecSigPriKey* SK){
	SK->i++;
	BIGNUM* next_sk = BN_new();
	power_function(next_sk,SK->sk,3*l,SK->N);
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

	power_function(r0,SIGN->sigma,3*l*(VK->T+1-j),VK->N);
	
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
	MSK->T = atoi(argv[2]); // setting T

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

