// Asiacrypto 2000 version
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <time.h>
#include <math.h>
#include <string.h>
FILE* file;

#define l 256

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
    BIGNUM* Id;
};
//Sign
struct FwSecSigSign{
	BIGNUM* sigma;
	BIGNUM* Y_prime;
	BIGNUM* Y;
	int j;
};
//ID
struct Identity{
	BIGNUM* Id;
};
// Secret parameter k
int gRSALength;	

BN_CTX* ctx;

// res = HASH1(Y||ID)
void HASH1(BIGNUM* res,BIGNUM* Y,BIGNUM* ID){
	char hash_digest[SHA_DIGEST_LENGTH];
	char temp[2048];
	SHA_CTX sha_ctx;
	SHA1_Init(&sha_ctx);

	BN_bn2bin(Y,temp);
	SHA1_Update(&sha_ctx,temp,BN_num_bytes(Y));

	BN_bn2bin(ID,temp);
	SHA1_Update(&sha_ctx,temp,BN_num_bytes(ID));
	SHA1_Final(hash_digest,&sha_ctx);

	BN_bin2bn(hash_digest,l/8,res);
}
//res = HASH2(Y||J||M)
void HASH2(BIGNUM* res,BIGNUM* Y_prime,int j,const char* M){
	
	char hash_digest[SHA_DIGEST_LENGTH];
	char temp[2048];
	SHA_CTX sha_ctx;
	SHA1_Init(&sha_ctx);

	sprintf(temp,"%d",j);
	SHA1_Update(&sha_ctx,M,strlen(M));
	SHA1_Update(&sha_ctx,temp,strlen(temp));
	BN_bn2bin(Y_prime,temp);
	SHA1_Update(&sha_ctx,temp,BN_num_bytes(Y_prime));

	SHA1_Final(hash_digest,&sha_ctx);
	BN_bin2bn(hash_digest,l/8,res);
	
}

//ret = base^(2^n)
void power_function(BIGNUM* ret ,BIGNUM* base , int n,BIGNUM* N){
	BIGNUM* two = BN_new();
	BIGNUM* expo =BN_new();
	BIGNUM* Expo = BN_new();
	BN_add(two,BN_value_one(),BN_value_one());//t is 2

	int len = floor(log10(abs(n)))+1;
	char* expo_str = (char *)malloc(len);
	sprintf(expo_str,"%d",n);
	BN_dec2bn(&expo, expo_str);
	BN_exp(Expo,two,expo,ctx);

	BN_mod_exp(ret,base,Expo,N,ctx);
	// printf("value of ret : ");
	// BN_print_fp(stdout,ret);
	// printf("\n");

	BN_free(Expo);
	BN_free(expo);
	BN_free(two);
}
void print_BN(BIGNUM* p, char* s){
	printf("value of %s",s);
	BN_print_fp(stdout,p);
	printf("\n");
}

void setup(struct FwSecMskKey* MSK, struct FwSecSigPubKey* VK)
{
	BIGNUM* temp= BN_new();
	BIGNUM* s = BN_new();//msk setting tool
	BIGNUM* p = BN_new();
    BIGNUM* q = BN_new();
//	BIGNUM* tempMSK=BN_new();

	while(1){
		if(BN_generate_prime_ex(p, gRSALength/2, 0, NULL, NULL, NULL))
		{
			//printf("p successed!\n");
			break;
		}	
	}
	while(1){
		if(BN_generate_prime_ex(q,gRSALength/2, 0, NULL, NULL, NULL)){
			//printf("q successed!\n");
			break;
		}
	}
	//BN_generate_prime_ex(p, gRSALength/2, 0, NULL, NULL, NULL);
	//BN_generate_prime_ex(q, gRSALength/2, 0, NULL, NULL, NULL);

	BN_mul(VK->N, p, q, ctx);//N of VK <-- setting N
//	BN_mul(MSK->N,p,q,ctx);// N of MSK <-- setting N
	BN_copy(MSK->N, VK->N);	
	MSK->i = 1; // i of MSK setting							
	BN_rand_range(s,VK->N);// s <-- Z_N
//	exp_twos_power(tempMSK,s,3*l); // msk_1 of MSK <-- S^2^3l setting 

	// power_function(MSK->msk,s,3*l,VK->N);
	// power_function(VK->U,s,3*l*(VK->T+1),VK->N);
	// BN_mod_inverse(VK->U,VK->U,VK->N,ctx);
	
	// print_BN(MSK->msk,"MSK->msk in setup : ");
	// print_BN(MSK->N,"MSK->N in setup : ");
	// printf("value of MSK->i : %d\n",MSK->i);
	// printf("value of MSK->T : %d\n",MSK->T);

	// print_BN(VK->U,"VK->U in setup : ");
	// print_BN(VK->N,"VK->N in setup : ");
	// printf("value of VK->i in setup: %d\n",VK->T);

	//hankyung modified
	//msk_1 of MSK <-- S^2^3l setting
	BIGNUM* phiN = BN_new();
	BIGNUM* p1 = BN_new();
	BIGNUM* q1 = BN_new();
	BIGNUM* tAdd1 = BN_new();
	BIGNUM* expo = BN_new();
	char temp_str[2048];
	BN_sub(p1, p, BN_value_one());	// p1 = p - 1
	BN_sub(q1, q, BN_value_one());	// q1 = q - 1
	BN_mul(phiN, p1, q1, ctx);		// phiN = (p - 1)(q - 1)
	BIGNUM* bnL = BN_new();
	BIGNUM* bn3L = BN_new();
	BN_dec2bn(&bnL, "160");			// edit "160" into argv[3] later....
	BN_add(bn3L, bnL, bnL);
	BN_add(bn3L, bn3L, bnL);		// bn3L = l * 3
	sprintf(temp_str,"%d",MSK->T+1);
	//printf("value of temp_str : %s\n",temp_str);

	BN_dec2bn(&tAdd1,temp_str);
	BN_mul(expo,bn3L,tAdd1,ctx); // expo = 3l(T+1);
	
	BIGNUM* bntwo = BN_new();	
	BN_add(bntwo, BN_value_one(), BN_value_one());	// bntwo = 2
	
	BN_mod_exp(temp, bntwo, bn3L, phiN, ctx);		// temp = 2 ^ 3l mod phiN
	BN_mod_exp(MSK->msk, s, temp, VK->N, ctx);		// msk = s ^ (2^3l) mod N
	//printf("msk_1 : ");
	//BN_print_fp(stdout, MSK->msk);
	//printf("\n");
	// end of setting msk_1
	


//	BN_mod(MSK->msk,tempMSK,VK->N,ctx);
//	exp_twos_power(temp, s, 3*l*(VK->T+1));// t1 <-- S^{2^{3l(T+1)}}
//	BN_mod_inverse(VK->U, temp, VK->N, ctx);// U of VK Setting
	
	//hankyung modified
	// U of VK setting
	//BIGNUM* bnT = BN_new();
	//BN_dec2bn(&bnT, "2048");							//edit "2048" into argv[2] later...
	//BN_add(bnT, bnT, BN_value_one());					// bnT = T + 1
	BN_mod_exp(VK->U, bntwo, expo, phiN, ctx);
	BN_mod_exp(VK->U, s, VK->U, VK->N, ctx);		
	BN_mod_inverse(VK->U, VK->U, VK->N, ctx);
	//printf("U : ");
	//BN_print_fp(stdout, VK->U);
	//printf("\n");
	// end of setting U
	
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
}

//KeyIssue(MSK_i , ID) -> SK
void keyIssue(struct FwSecMskKey* MSK, struct Identity* ID,struct FwSecSigPriKey* SK,struct FwSecSigPubKey* VK)
{
    BIGNUM* r = BN_new();
	BIGNUM* R  = BN_new();
	BIGNUM* Y = BN_new();
	BIGNUM* hash1 = BN_new();
	BIGNUM* msk_temp = BN_new();
	
	BN_copy(SK->N,MSK->N);
	SK->T = MSK->T;
	SK->i = MSK->i;

	BN_rand_range(r,MSK->N); // r <- Zn*
    BN_mod_exp(R,MSK->msk,r,VK->N,ctx); ///  R <- msk^r mod N
    BN_mod_exp(Y,VK->U,r,VK->N,ctx);
    BN_mod_inverse(Y,Y,VK->N,ctx);
    BN_copy(SK->Y,Y);

	//power_function(Y,R,3*l*(MSK->T+1-MSK->i),MSK->N);// Y is (R)^(2^(3l(T+1-i)))
	//BN_copy(SK->Y,Y);
	


	HASH1(hash1,Y,ID->Id);
	//print_BN(ID->Id," ID->Id in KeyIssue : ");
	//print_BN(hash1," HASH1 in KeyIssue : ");
	BN_mod_exp(msk_temp,MSK->msk,hash1,MSK->N,ctx);//msk^h1
	//print_BN(msk_temp," msk^hash1 mod in KeyIssue : ");
	BN_mod_mul(SK->sk,R,msk_temp,MSK->N,ctx);
	
	// print_BN(SK->sk," SK->sk is (R*msk^hash1) in KeyIssue : ");// R
	// print_BN(SK->Y," SK->Y in KeyIssue : ");
	// print_BN(SK->N," SK->N in KeyIssue : ");
	// printf("value of SK->T : %d\n",SK->T);
	// printf("value of SK->i : %d\n",SK->i);

    BN_free(r);
	BN_free(R);
	BN_free(Y);
	BN_free(hash1);
	BN_free(msk_temp);
}

void Sign(struct Identity* ID,int j,struct FwSecSigPriKey* SK,const char* M,struct FwSecSigSign* SIGN,struct FwSecSigPubKey* VK){
	BIGNUM* r = BN_new();
    BIGNUM* R = BN_new(); //R' storage
	
    BIGNUM* hash1 = BN_new();
    BIGNUM* hash2 = BN_new(); // H_2(Y'||j||M) storage 
	
    BIGNUM* t = BN_new();
	BIGNUM* y = BN_new();

    BIGNUM* temp = BN_new();
    BIGNUM* temp1 = BN_new();
	SIGN->j = SK->i;

    BN_rand_range(r,VK->N);
    BN_mod_exp(R,SK->sk,r,VK->N,ctx);
	//BN_rand_range(R,SK->N);//
    HASH1(hash1,SK->Y,SK->Id);
    BN_mod_exp(temp,VK->U,hash1,VK->N,ctx);
    BN_mod_inverse(temp,temp,VK->N,ctx);
    BN_mul(temp1,SK->Y,temp,ctx);
    BN_mod_exp(SIGN->Y_prime,temp1,r,VK->N,ctx);

	//power_function(y,R,3*l*(SK->T+1-j),SK->N);
	//BN_copy(SIGN->Y_prime,y);
	BN_copy(SIGN->Y,SK->Y);

	HASH2(hash2,SIGN->Y_prime,j,M);

	BN_mod_exp(t,SK->sk,hash2,SK->N,ctx);
	BN_mod_mul(SIGN->sigma,R,t,SK->N,ctx);

	// print_BN(t," sk^HASH2 mod N in Sign : ");
	// print_BN(SIGN->sigma," SIGN->sigma mod N in Sign : ");
	// print_BN(SIGN->Y_prime," SIGN->Y_Prime mod N in Sign : ");
	// print_BN(SIGN->Y," SIGN->Y in Sign : ");
	// print_BN(hash2," hash2 in Sign : ");

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

	power_function(left_hand_side,SIGN->sigma,3*l*(VK->T+1-j),VK->N);


	BN_mul(h1h2,h1,h2,ctx);
	BN_mod_exp(r2, SIGN->Y, h2,VK->N ,ctx); // Y^h2
	BN_mod_exp(r3,VK->U,h1h2,VK->N,ctx); // U^h1h2
	BN_mod_inverse(r4, r3,VK->N, ctx);// (1/U)^h1h2 of VK Setting
	BN_mod_mul(r1,r2,r4,VK->N,ctx);//r1 => 

	BN_mod_mul(right_hand_side,SIGN->Y_prime,r1,VK->N,ctx);


	int flag = BN_cmp(left_hand_side,right_hand_side);
	// printf("value of Left_hand :");
	// BN_print_fp(stdout,left_hand_side);
	// printf("\n");
	// printf("value of Right_hand :");
	// BN_print_fp(stdout,right_hand_side);
	// printf("\n");

	//SK verify
	// BIGNUM* left=BN_new();
	// BIGNUM* right = BN_new();
	// BIGNUM* t0 = BN_new();
	// BIGNUM* t1 = BN_new();
	// BN_mod_exp(t0,VK->U,h1,VK->N,ctx);
	// BN_mod_inverse(t1,VK->U,VK->N,ctx); //(1/u)^h1
	// BN_mod_mul(left,SIGN->Y,t1,VK->N,ctx);

	// power_function(right,SK->sk,3*l*VK->T,VK->N);
	// int test = BN_cmp(left,right);
	// printf("test verify : %d\n",test);


	//print_BN(ID->Id," ID->Id in verify : ");
	// print_BN(h1," HASH1 in verify : ");
	// print_BN(h2," HASH2 in verify : ");
	// print_BN(r2," Y^HASH2 mod N in verify : ");
	// print_BN(r3," U^(HASH1*HASH2) mod N in verify : ");
	// print_BN(r4," (1/U)^(HASH1*HASH2) mod N in verify : ");
	// print_BN(r1," (Y^HASH2)*(1/U)^(HASH1*HASH2) mod N in verify : ");
	// print_BN(right_hand_side," Y_prime*(Y^HASH2)*(1/U)^(HASH1*HASH2) mod N in verify : ");
	// print_BN(left_hand_side," sigma^3l(T+1-j) mod N in verify :  ");


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
	clock_t start, end;
	
	float total_setup = 0,total_keyIssue=0,total_sign=0,total_verify=0,total_mskupdate=0,total_ukupdate=0;
	
	ctx = BN_CTX_new();
	const char* message = "A";
	const char* message2 = "B";
	struct FwSecMskKey *MSK = malloc(sizeof(struct FwSecMskKey));
	//msk private key
	MSK->N = BN_new();
	MSK->msk = BN_new();
	struct FwSecSigPubKey *VK = malloc(sizeof(struct FwSecSigPubKey));
	//public key
	VK->U = BN_new();
	VK->N = BN_new();

	struct Identity *ID = malloc(sizeof(struct Identity));
	ID->Id = BN_new();
	
	//argument : rsa_bit_length period_length
	if(argc < 3){
		printf("argument : k T is needed\n");
		return 0;
	} 
	gRSALength = atoi(argv[1]);	// k
	VK->T = atoi(argv[2]);	// setting T
	MSK->T = atoi(argv[2]); // setting T

	printf("----------------------setup start--------------------\n");
	start = clock();
	setup(MSK,VK);
	end=clock();
	total_setup+=(float)(end-start)/CLOCKS_PER_SEC;
	printf("setup :  %f\n", (float)(end-start)/CLOCKS_PER_SEC);
	printf("----------------------setup ended--------------------\n");

	BN_rand_range(ID->Id,VK->N);
	// initialize SK
	struct FwSecSigPriKey *SK = malloc(sizeof(struct FwSecSigPriKey));
	SK->N = BN_new();
	SK->Y = BN_new();
	SK->sk = BN_new();
    SK->Id = BN_new();
    BN_copy(SK->Id,ID->Id);
	printf("----------------------keyIssue start-----------------\n");
	start = clock();
	keyIssue(MSK,ID,SK,VK);
	end=clock();
	total_keyIssue+=(float)(end-start)/CLOCKS_PER_SEC;
	printf("KeyIssue :  %f\n", (float)(end-start)/CLOCKS_PER_SEC);
	printf("----------------------keyIssue ended-----------------\n");

	struct FwSecSigSign *SIGN = malloc(sizeof(struct FwSecSigSign));
	SIGN->Y_prime=BN_new();
	SIGN->Y = BN_new();
	SIGN->sigma = BN_new();

	printf("----------------------Sign start---------------------\n");
	start = clock();
	Sign(ID,SK->i,SK,message,SIGN,VK);
	end = clock();
	total_sign+=(float)(end-start)/CLOCKS_PER_SEC;
	printf("Sign %f\n", (float)(end-start)/CLOCKS_PER_SEC);
	printf("----------------------Sign ended---------------------\n");

	int flag;
	printf("----------------------Verify start-------------------\n");
	start = clock();
	flag = verify(ID,message,SIGN,VK,SIGN->j);
	end=clock();
	total_verify+=(float)(end-start)/CLOCKS_PER_SEC;
	printf("Verify : %f\n", (float)(end-start)/CLOCKS_PER_SEC);
	printf("----------------------Verify ended-------------------\n");
	

	//printf("----------------------MSKUpdate start----------------\n");
	start = clock();
	MSKupdate(MSK);
	end = clock();
	total_mskupdate+=(float)(end-start)/CLOCKS_PER_SEC;
	//printf("MSKUpdate : %f\n", (float)(end-start)/CLOCKS_PER_SEC);
	//printf("----------------------MSKUpdate ended----------------\n");

	//keyIssue(MSK,ID,SK); // MSKUPdate version
	//printf("----------------------UKUpdate start-----------------\n");
	start = clock();
	UKupdate(SK); // UKUpdate version
	end=clock();
	total_ukupdate += (float)(end-start)/CLOCKS_PER_SEC;
	//printf("UKUpdate : %f\n", (float)(end-start)/CLOCKS_PER_SEC);
	//printf("----------------------UKUpdate ended-----------------\n");

	if(flag == 0){
		printf("Verify successed\n");
	}else{
		printf("Verify failed\n");	
	}


	//Sign(ID,SK->i,SK,message,SIGN);
	//flag = verify(ID,message,SIGN,VK,SIGN->j);
	//printf("Value of update flag => %d\n",flag);

	BN_CTX_free(ctx);
	
	printf("%d %d",BN_num_bytes(VK->N),BN_num_bits(VK->U));

	printf("VK KEY SIZE : %d\n",BN_num_bytes(VK->N)+BN_num_bytes(VK->U)+sizeof(VK->T));
	printf("MSK KEY SIZE : %d\n",BN_num_bytes(MSK->N)+BN_num_bytes(MSK->msk)+sizeof(MSK->i)+sizeof(MSK->T));
	printf("SIGN KEY SIZE : %d\n",BN_num_bytes(SIGN->sigma)+BN_num_bytes(SIGN->Y_prime)+BN_num_bytes(SIGN->Y)+sizeof(SIGN->j));
	printf("SK KEY SIZE : %d\n",BN_num_bytes(SK->N)+BN_num_bytes(SK->Y)+BN_num_bytes(SK->sk)+sizeof(SK->T)+sizeof(SK->i)+BN_num_bytes(SK->Id));
	printf("ID KEY SIZE : %d\n",BN_num_bytes(ID->Id));

	printf("Setup Average time(3 time) : %f\n",total_setup);
	printf("Keyissue Average time(3 time) : %f\n",total_keyIssue);
	printf("Sign Average time(3 time) : %f\n",total_sign);
	printf("Verify Average time(3 time) : %f\n",total_verify);
	printf("MSAKupdate Average time(3 time) : %f\n",total_mskupdate);
	printf("UKupdate Average time(3 time) : %f\n",total_ukupdate);
	
	return 0;
}
