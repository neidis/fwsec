#define _CRT_SECURE_NO_WARNINGS
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include<stdio.h>
//#include <iostream>
#include <time.h>
#include <math.h>
#include <string.h>
#include <stdlib.h>
#include<vector.h>
#include<sstream>
#include<iomanip>
#include<fstream>
using namespace std;
FILE* file;
#define l 256


//PK
struct FAS_PubKey {
	BIGNUM* N;
	int T;
	int n;
	BIGNUM* N_prime;
	BIGNUM* D;
	BIGNUM* U;
	BIGNUM* X;
	BIGNUM* Y;
};

struct FAS_BlindProof {
	BIGNUM* W;
	BIGNUM* seta;
	BIGNUM* h;
};

//SK
struct FAS_PriKey {
	BIGNUM* N;
	int T;
	int n;
	BIGNUM* N_prime;
	BIGNUM* X;
	BIGNUM* Y;
	BIGNUM* v;
	int j;// current period
	int t_j;
	BIGNUM* E_j;
	BIGNUM* S_t;
	BIGNUM* B_j_1;
	struct FAS_BlindProof* eta_j_1;
};

// eta => proof of blind factor

//Sign
struct FAS_Sign {
	int i;
	int j;
	BIGNUM* sigma;
	BIGNUM* E;
	struct FAS_BlindProof* pre_eta;
	struct FAS_BlindProof* post_eta;
};

BN_CTX* ctx;

void print_BN(BIGNUM* p, string s) {
	cout << s << "  ";
	char *a;
	a = BN_bn2dec(p);
	cout << a << endl;
}

// res = HASH1(j||t||E||M)
void HASH1(BIGNUM* res, int j, int t, BIGNUM* E, string M) {
	unsigned char hash_digest[SHA256_DIGEST_LENGTH];
	char temp[2048];
	SHA256_CTX sha256;
	SHA256_Init(&sha256);

	sprintf(temp, "%d", j);
	SHA256_Update(&sha256, temp, strlen(temp));

	sprintf(temp, "%d", t);
	SHA256_Update(&sha256, temp, strlen(temp));

	BN_bn2bin(E, (unsigned char*)temp);
	SHA256_Update(&sha256, temp, BN_num_bytes(E));

	SHA256_Update(&sha256, M.c_str(), strlen(M.c_str()));
	SHA256_Final(hash_digest, &sha256);

	BN_bin2bn(hash_digest, l / 8, res);
}
//res = HASH2(W||X)
void HASH2(BIGNUM* res, BIGNUM* W, BIGNUM* J) {
	cout << "---------------------------HASH2-----------------------------" << endl;
	unsigned char hash_digest[SHA256_DIGEST_LENGTH];
	unsigned char temp[2048];
	SHA256_CTX sha256;
	SHA256_Init(&sha256);

	BN_bn2bin(W, temp);
	SHA256_Update(&sha256, temp, BN_num_bytes(W));
	BN_bn2bin(J, temp);
	SHA256_Update(&sha256, temp, BN_num_bytes(J));


	SHA256_Final(hash_digest, &sha256);
	stringstream ss;
	for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
		ss << hex << setw(2) << setfill('0') << (int)hash_digest[i];

	BN_hex2bn(&res, ss.str().c_str());
	//BN_bin2bn(hash_digest, l / 8, res);
}

void HASH3(BIGNUM* res, BIGNUM* base,int n, BIGNUM* N,BIGNUM* phiN) {
	BIGNUM* three = BN_new();
	BIGNUM* dec = BN_new();
	BIGNUM* expo = BN_new();
	BIGNUM* EXPO = BN_new();
	BIGNUM* two = BN_new();
	BN_add(two, BN_value_one(), BN_value_one());
	BN_add(three, BN_value_one(), BN_value_one());
	BN_add(three, BN_value_one(), three);

	int len = floor(log10(abs(n))) + 1;
	char* expo_str = (char *)malloc(len);
	sprintf(expo_str, "%d", n);
	BN_dec2bn(&expo, expo_str);
	if (phiN == NULL)
		BN_exp(EXPO, two, expo, ctx);
	else
		BN_mod_exp(EXPO, two, expo, phiN, ctx);

	BN_mod_exp(res, base, EXPO, N, ctx);
	
}


// n to BIGNUM(BN)
BIGNUM* intTobn(int n) {
	BIGNUM* BN = BN_new();
	int len = floor(log10(abs(n))) + 1;
	char* str = (char*)malloc(len);
	sprintf(str, "%d", n);
	BN_dec2bn(&BN, str);
	return BN;
}

//ret = base^(2^n)
void power_function(BIGNUM* ret, BIGNUM* base, int n, BIGNUM* N, BIGNUM* phiN) {
	BIGNUM* two = BN_new();
	BIGNUM* expo = BN_new();
	BIGNUM* Expo = BN_new();
	BN_add(two, BN_value_one(), BN_value_one());//t is 2

	int len = floor(log10(abs(n))) + 1;
	char* expo_str = (char *)malloc(len);
	sprintf(expo_str, "%d", n);
	BN_dec2bn(&expo, expo_str);
	if (phiN == NULL)
		BN_exp(Expo, two, expo, ctx);
	else
		BN_mod_exp(Expo, two, expo, phiN, ctx);

	BN_mod_exp(ret, base, Expo, N, ctx);


	BN_free(Expo);
	BN_free(expo);
	BN_free(two);
}

// expo : 2^2l(T+1)
void pSig(struct FAS_BlindProof* eta, struct FAS_PubKey* PK, BIGNUM* B, BIGNUM* W) {
	cout << "---------------------------pSig start-----------------------------" << endl;
	eta->W = BN_new();
	eta->h = BN_new();
	eta->seta = BN_new();
	BIGNUM* r = BN_new();
	BIGNUM* x = BN_new();

	BN_copy(eta->W, W); // set eta->W
	BN_rand_range(r, PK->N);

	BIGNUM* I = BN_new();
	BIGNUM* J = BN_new();
	BN_mod_exp(I, PK->X, r, PK->N, ctx);
	BN_mod_exp(J, PK->Y, r, PK->N, ctx);

	HASH2(eta->h, W, J); // H2(W || J)

	BIGNUM* temp = BN_new();
	BN_mod_exp(temp, B, eta->h, PK->N, ctx);
	BN_mod_mul(eta->seta, I, temp, PK->N, ctx);

	BN_free(temp);
	BN_free(r);
	BN_free(I);
	BN_free(J);
	cout << "---------------------------pSig end-----------------------------" << endl;
}

void setup(int k, int L, int T, int n, struct FAS_PubKey* PK, struct FAS_PriKey* SK)
{
	
	clock_t start, end;

	BIGNUM* p = BN_new();
	BIGNUM* q = BN_new();
	BIGNUM* phiN = BN_new();// (p-1) * (q-1)
	BIGNUM* s = BN_new();
	BIGNUM* two = BN_new(); // BIGNUM 2
	BIGNUM* three = BN_new();
	BIGNUM* N = BN_new();
	BIGNUM* four = BN_new();
	int EXPO = 2 * l*(T + 1); //

	BN_add(two, BN_value_one(), BN_value_one());
	BN_add(three, BN_value_one(), two);
	BN_add(four, two, two);
	PK->T = T; // set PK T
	SK->T = T; // set SK T
	PK->n = n; // set PK n
	SK->n = n; // set SK n
	SK->j = 1; // set SK j
	SK->t_j = 1; // set SK t_j
	start = clock();
	while (1) {
		if (BN_generate_prime_ex(p, k / 2, true, NULL, NULL, NULL))
		{
			break;
		}
	}
	while (1) {
		if (BN_generate_prime_ex(q, k / 2, true, NULL, NULL, NULL)) {
			if (BN_cmp(p, q))
				break;
		}
	}
	BN_mul(N, p, q, ctx);//N of PK <-- setting N
	BN_copy(PK->N, N); // set PK N
	BN_copy(SK->N, N); // set SK N
	BN_sub(p, p, BN_value_one());;
	BN_sub(q, q, BN_value_one());
	BN_mul(phiN, p, q, ctx); // phi of N
	end = clock();
	cout <<"p q N 생성까지의 시간" <<(float)(end - start) / CLOCKS_PER_SEC<< endl;


	start = clock();
	BN_rand_range(s, N);// s <-- Z_N



	power_function(PK->U, s, EXPO, N, phiN); // set PK U

	BN_rand_range(SK->X, N); // set SK X
	power_function(SK->Y, SK->X, EXPO, N, phiN); // set SK Y
	BN_copy(PK->X, SK->X); // set PK X
	BN_copy(PK->Y, SK->Y); // set PK Y
	end = clock();
	cout << "U X Y 생성까지의 시간" << (float)(end - start) / CLOCKS_PER_SEC << endl;
	start = clock();
	BIGNUM* p_prime = BN_new();// p'
	BIGNUM* q_prime = BN_new();// q'
	BIGNUM* N_prime = BN_new();// p'*q'
	BIGNUM* phiN_prime = BN_new(); // (p'-1)(q'-1)


	while (1) {
		if (BN_generate_prime_ex(p_prime, k / 2, true, NULL, NULL, NULL))
		{
			break;
		}
	}
	while (1) {
		if (BN_generate_prime_ex(q_prime, k / 2, true, NULL, NULL, NULL)) {
			if (BN_cmp(p_prime, q_prime))
				break;
		}
	}
	BN_mul(N_prime, p_prime, q_prime, ctx); // N' = p'* q'
	BN_sub(p_prime, p_prime, BN_value_one()); // p' -= 1
	BN_sub(q_prime, q_prime, BN_value_one()); // q'-= 1
	BN_mul(phiN_prime, p_prime, q_prime, ctx); // phiN'  = p'-1 * q'-1
	end = clock();
	cout << "p' q' N' 생성까지의 시간" << (float)(end - start) / CLOCKS_PER_SEC << endl;
	start = clock();
	BIGNUM* four_phiN_prime = BN_new();
	BN_div(four_phiN_prime, NULL, phiN_prime, four, ctx); // phi(N')/4

	BN_copy(PK->N_prime, N_prime); // set PK N_prime
	BN_copy(SK->N_prime, N_prime); // set SK N_prime

	BIGNUM* C = BN_new();
	BN_rand_range(C, N_prime); // C <- Z*n'
	HASH3(PK->D, C, n, N_prime, phiN_prime);
	power_function(PK->D, C, n, N_prime, four_phiN_prime); //  set PK D

	BN_mod_inverse(SK->v,two,four_phiN_prime,ctx);
	

	BIGNUM* r0 = BN_new();
	BIGNUM* W = BN_new();
	BN_rand_range(r0, N);

	BN_mod_exp(SK->B_j_1, SK->X, r0, N, ctx); // set SK B_j_1
	BN_mod_exp(W, SK->Y, r0, N, ctx);

	//print_BN(PK->D, "D : ");
	//print_BN(SK->v, "SK v : ");
	BN_mod_exp(SK->E_j, PK->D, SK->v, N_prime, ctx); // set SK->E_j
	
	power_function(SK->S_t, s, 2 * l, N, phiN); // set SK S_t
	pSig(SK->eta_j_1, PK, SK->B_j_1, W); // set SK eta_j_1
	end = clock();
	cout << "p' q' N' 뒤" << (float)(end - start) / CLOCKS_PER_SEC << endl;

	BN_free(s);
	BN_free(p);
	BN_free(q);
	BN_free(phiN);
	BN_free(two);
	BN_free(r0);
	BN_free(C);
	BN_free(W);
	BN_free(p_prime);
	BN_free(q_prime);
	BN_free(N_prime);
	BN_free(phiN_prime);
	BN_free(N);
}

void Sig(struct FAS_PubKey* PK, struct FAS_PriKey* SK, string M, struct FAS_Sign* Sign) {
	if (SK->j > SK->T + 1 || SK->t_j >= SK->n) // 
		return;
	else {
		BIGNUM* c = BN_new();
		HASH1(c, SK->j, SK->t_j, SK->E_j, M);
		
		/*cout << "j in Sig : " << SK->j << endl;
		cout << "t in Sig : " << SK->t_j << endl;
		cout << "E in Sig : " << SK->E_j << endl;
		cout << "M in Sig : " << M << endl;*/



		BIGNUM* r = BN_new();
		BIGNUM* R = BN_new();
		BIGNUM* t1 = BN_new();
		BIGNUM* W = BN_new(); // W_j
		BN_rand_range(r, SK->N);
		BN_mod_exp(R, SK->X, r, SK->N, ctx);
		BN_mod_exp(t1, SK->Y, r, SK->N, ctx);
		BN_mod_mul(W, SK->eta_j_1->W, t1, SK->N, ctx);// W_j = W_j-1 * Y^r

		BIGNUM* t2 = BN_new();
		BN_mod_exp(t2, SK->S_t, c, SK->N, ctx);
		BN_mod_mul(Sign->sigma, R, t2, SK->N, ctx); // set Z[SIGN]

		BN_mod_mul(SK->B_j_1, SK->B_j_1, R, SK->N, ctx);

		struct FAS_BlindProof* BP = (struct FAS_BlindProof*)malloc(sizeof(struct FAS_BlindProof));
		BP->h = BN_new();
		BP->seta = BN_new();
		BP->W = BN_new();
		pSig(BP, PK, SK->B_j_1, W);
		Sign->i = SK->j; // set j[SIGN]
		Sign->j = SK->j; // set j[SIGN]
		BN_copy(Sign->E, SK->E_j);
		Sign->pre_eta = SK->eta_j_1; // set eta_j-1[SIGN]
		Sign->post_eta = BP; // set eta_j[SIGN]

		SK->j++;

		BN_mod_exp(SK->E_j, SK->E_j, SK->v, SK->N_prime, ctx);
		SK->eta_j_1 = BP;
	}
}

void Upd(struct FAS_PriKey* SK) {
	if (SK->j >= (SK->T + 1))
		return;
	else {
		power_function(SK->S_t, SK->S_t, 2 * l, SK->N, NULL);
		SK->t_j++;
	}
}

//expo : 2^2l(T+1)
int pVer(struct FAS_BlindProof* BP, BIGNUM* N, int expo) {
	cout << "---------------------------pVer start-----------------------------" << endl;
	BIGNUM* J = BN_new();
	BIGNUM* t1 = BN_new();//seta^expo
	BIGNUM* t2 = BN_new();
	BIGNUM* t3 = BN_new();
	BIGNUM* t4 = BN_new();
	BIGNUM* t5 = BN_new();
	power_function(t1, BP->seta, expo, N, NULL);

	/*BN_mod_exp(t2, BP->W, BP->h,N,ctx);*/
	BN_mod_exp(t2, BP->W, BP->h, N, ctx);
	BN_mod_inverse(t3, t2, N, ctx);
	BN_mod_mul(J, t1, t3, N, ctx);

	HASH2(t5, BP->W, J);

	cout << "---------------------------pVer end-----------------------------" << endl;
	if (!BN_cmp(BP->h, t5)) return 1;
	else return 0;
}

int Ver(struct FAS_PubKey* PK, struct FAS_Sign* Sign, struct FAS_PriKey* SK, string M) {
	BIGNUM* c = BN_new();
	int EXPO = 2 * l*(PK->T + 1);
	HASH1(c, Sign->j, SK->t_j, Sign->E, M);

	if (pVer(Sign->pre_eta, PK->N, EXPO)) {
		if (pVer(Sign->post_eta, PK->N, EXPO)) {
			BIGNUM* hash = BN_new();
			//print_BN(Sign->E, " Sign E in Ver : ");
			//cout << "Sign j in Ver : " << Sign->j << endl;
			HASH3(hash, Sign->E, Sign->j, PK->N_prime, NULL);
			//print_BN(hash, "hash : ");
			//print_BN(PK->D, "PK D : ");

			if (!BN_cmp(hash, PK->D)) {
				BIGNUM* res1 = BN_new();
				BIGNUM* res2 = BN_new();
				BIGNUM* res3 = BN_new();

				power_function(res1, Sign->sigma, EXPO, PK->N, NULL);
				BN_mod_inverse(res2, Sign->pre_eta->W, PK->N, ctx);
				BN_mod_mul(res2, res2, Sign->post_eta->W, PK->N, ctx);
				power_function(res3, PK->U, 2 * l*Sign->j, PK->N, NULL);
				BN_mod_exp(res3, res3, c, PK->N, ctx);
				BN_mod_mul(res3, res3, res2, PK->N, ctx);
				if (!BN_cmp(res1,res3)) {
					cout << "Verify successed!" << endl;
					return 1;
				}
				else {
					cout << "Verify failed!" << endl;
					return 0;
				}
					
			}
			else {
				cout << "HASH Value is invalid" << endl;
				return 0;
			}
		}
		else {
			cout << "return value of pVer in j is 0" << endl;
			return 0;
		}
	}
	else
	{
		cout << "return value of pVer in j-1 is 0" << endl;
		return 0;
	}
}

struct FAS_Sign* Agg(struct FAS_Sign* pre_Sign, struct FAS_Sign* post_Sign,struct FAS_PubKey* PK) {
	struct FAS_Sign* AggSign = (struct FAS_Sign*)malloc(sizeof(struct FAS_Sign));
	AggSign->E = BN_new();
	AggSign->sigma = BN_new();
	AggSign->pre_eta = (struct FAS_BlindProof*)malloc(sizeof(struct FAS_BlindProof));
	AggSign->post_eta = (struct FAS_BlindProof*)malloc(sizeof(struct FAS_BlindProof));

	AggSign->i = pre_Sign->i;
	AggSign->j = post_Sign->j;
	BN_copy(AggSign->E, post_Sign->E);
	AggSign->pre_eta = pre_Sign->pre_eta;
	AggSign->post_eta = post_Sign->post_eta;
	BN_mod_mul(AggSign->sigma, pre_Sign->sigma, post_Sign->sigma,PK->N ,ctx);
	
	return AggSign;
}


int AggVer(struct FAS_PubKey* PK, struct FAS_Sign* Sign,vector<int> t ,vector<string> M) {
	
	BIGNUM* temp = BN_new();
	vector<BIGNUM*> c(M.size());
	BIGNUM* F = BN_new();
	BN_add(F, F, BN_value_one());
	BIGNUM* two = BN_new();
	BIGNUM* three = BN_new();
	int expo = 2 * l*(PK->T + 1);
	BN_add(two, BN_value_one(), BN_value_one());
	BN_add(three, BN_value_one(), two);
	HASH3(temp, Sign->E, Sign->j, PK->N_prime,NULL);

	/*cout << "AggVer Sign->j : " << Sign->j << endl;
	cout << "AggVer Sign->i : " << Sign->i << endl;
	cout << "M.size() : " << M.size() << endl;
	cout << "t.size() : " << t.size() << endl;*/

	if (!BN_cmp(temp,PK->D)) {
		for (int m = Sign->j; m >=Sign->i ; m--) {
			c.at(m-Sign->i) = BN_new();
			HASH1(c.at(m-Sign->i), m,t.at(m-Sign->i),Sign->E, M.at(m-Sign->i));
			/*cout << "m in AggVer : " << m << endl;
			cout << "t in AggVer : " << t.at(m-Sign->i) << endl;
			cout << "Sign->E in AggVer : " << Sign->E << endl;
			cout << "M.at(m) in AggVer : " << M.at(m-Sign->i) << endl;*/
			BN_mod_exp(Sign->E, Sign->E, two,PK->N_prime, ctx);
		}

		for (int k = Sign->j; k >= Sign->i; k--) {
			BIGNUM* temp1 = BN_new();
			power_function(temp1, PK->U, 2 * l*k, PK->N, NULL);
			BN_mod_exp(temp1, temp1, c.at(k-1), PK->N, ctx);
			BN_mod_mul(F, F, temp1, PK->N,ctx);
		}

		if (pVer(Sign->pre_eta,PK->N,expo)) {
			if (pVer(Sign->post_eta, PK->N, expo)) {
				BIGNUM* temp2 = BN_new();
				BIGNUM* temp3 = BN_new();
				BIGNUM* temp4 = BN_new();

				power_function(temp2, Sign->sigma, expo, PK->N,NULL);
				BN_mod_inverse(temp3, Sign->pre_eta->W, PK->N, ctx);
				BN_mod_mul(temp3, temp3, Sign->post_eta->W, PK->N, ctx);
				BN_mod_mul(temp4, temp3, F, PK->N, ctx);
				if (!BN_cmp(temp2,temp4))
				{
					cout << "verify! in AggVer" << endl;
					return 1;
				}
				else {
					cout << "invalid F , Z" << endl;
					return 0;
				}
			}
			else {
				cout << "return value of pVer in j is 0" << endl;
				return 0;
			}
		}
		else {
			cout << "return value of pVer in j-1 is 0" << endl;
			return 0;
		}
	}
	else {
		cout << "invalid HASH value" << endl;
		return 0;
	}
}

//int main(int argc, const char* argv[])
int main()
{
	//ofstream testfile("result2.txt");

	if (!testfile.is_open()) {
		return 0;
	}

	//int k, T, n;
	float time;
	cin >> k >> T >> n;
	// testfile << "k : " << k << endl;
	// testfile << "l : " << l<< endl;
	// testfile << "T : " << T << endl;
	// testfile << "n : " << n << endl;
	clock_t start, end;

	ctx = BN_CTX_new();

	//struct FAS_BlindProof* BP = (struct FAS_BlindProof*)malloc(sizeof(struct FAS_BlindProof));
	//BP->h = BN_new();
	//BP->seta = BN_new();
	//BP->W = BN_new();
	//
	//BIGNUM* two = BN_new();
	//
	//BIGNUM* p = BN_new();
	//BIGNUM* q = BN_new();
	//BIGNUM* N = BN_new();
	//while (1) {
	//	if (BN_generate_prime_ex(p, k / 2, 0, NULL, NULL, NULL))
	//	{
	//		//printf("p successed!\n");
	//		break;
	//	}
	//}
	//while (1) {
	//	if (BN_generate_prime_ex(q, k / 2, 0, NULL, NULL, NULL)) {
	//		if(BN_cmp(p,q))
	//			break;
	//	}
	//}

	//BN_mul(N, p, q, ctx);//N of PK <-- setting N

	//print_BN(q, "q ::: ");
	//print_BN(p, "p ::: ");
	//print_BN(N, "N ::: ");

	//BN_rand_range(two, N);
	//BIGNUM* a = BN_new();
	//power_function(a, two, 2 * l*(T + 1), N, NULL);
	//pSig(BP, two, a, two, a, N);
	//cout << pVer(BP, N, 2 * l*(T + 1)) << endl;


	float total_setup = 0, total_keyIssue = 0, total_sign = 0, total_verify = 0, total_mskupdate = 0, total_ukupdate = 0;


	vector<string> Ms;
	vector<int> ts;
	string M = "A";
	Ms.push_back("s");
	Ms.push_back("n");
	Ms.push_back("p");

	vector<string> Fake_Ms;
	Fake_Ms.push_back("a");
	Fake_Ms.push_back("a");
	Fake_Ms.push_back("a");

	struct FAS_PubKey *PK = (FAS_PubKey*)malloc(sizeof(struct FAS_PubKey));
	PK->N = BN_new();
	PK->D = BN_new();
	PK->U = BN_new();
	PK->X = BN_new();
	PK->Y = BN_new();
	PK->N_prime = BN_new();


	struct FAS_PriKey *SK = (FAS_PriKey*)malloc(sizeof(struct FAS_PriKey));
	SK->N = BN_new();
	SK->N_prime = BN_new();
	SK->X = BN_new();
	SK->Y = BN_new();
	SK->v = BN_new();
	SK->E_j = BN_new();
	SK->S_t = BN_new();
	SK->B_j_1 = BN_new();
	SK->eta_j_1 = (FAS_BlindProof*)malloc(sizeof(struct FAS_BlindProof));

	//argument : rsa_bit_length period_length
	if (argc < 3) {
	printf("argument : k T is needed\n");
	return 0;
	}

	int k = atoi(argv[1]);	// k
	int T = atoi(argv[2]);	// set T
	int n = atoi(argv[3]);

	printf("----------------------setup start--------------------\n");
	start = clock();
	setup(k, l, T, n, PK, SK);
	end = clock();
	time = (float)(end - start) / CLOCKS_PER_SEC;
	//testfile << "Setup time: " << time << endl;
	//total_setup += (float)(float)(end - start) / CLOCKS_PER_SEC;
	//printf("setup :  %f\n", (float)(float)(end - start) / CLOCKS_PER_SEC);
	printf("----------------------setup ended--------------------\n");
	
	struct FAS_Sign* Sign = (struct FAS_Sign*)malloc(sizeof(struct FAS_Sign));
	Sign->E = BN_new();
	Sign->post_eta = (FAS_BlindProof*)malloc(sizeof(struct FAS_BlindProof));
	Sign->pre_eta = (FAS_BlindProof*)malloc(sizeof(struct FAS_BlindProof));
	Sign->sigma = BN_new();
	printf("----------------------sig0 start----------------------\n");
	start = clock();
	Sig(PK,SK, Ms.at(0), Sign);
	ts.push_back(SK->t_j);
	//cout << "SIGN 0 SK->t : " << SK->t_j << endl;
	end = clock();
	time = (float)(end - start) / CLOCKS_PER_SEC;
	//testfile << "Sign 0 time: " << time << endl;
	//total_setup += (float)(float)(end - start) / CLOCKS_PER_SEC;
	//printf("sig :  %f\n", (float)(float)(end - start) / CLOCKS_PER_SEC);
	printf("----------------------sig0 ended--------------------\n");

	printf("----------------------single verify start--------------------\n");
	start = clock();
	Ver(PK,Sign,SK,Ms.at(0));
	end = clock();
	time = (float)(end - start) / CLOCKS_PER_SEC;
	//total_setup += (float)(float)(end - start) / CLOCKS_PER_SEC;
	//printf("verify :  %f\n", (float)(float)(end - start) / CLOCKS_PER_SEC);
	//testfile << "Verify time: " << time << endl;
	printf("----------------------single verify ended--------------------\n");

	printf("----------------------First update start--------------------\n");
	start = clock();
	Upd(SK);
	end = clock();
	time = (float)(end - start) / CLOCKS_PER_SEC;
	//total_setup += (float)(float)(end - start) / CLOCKS_PER_SEC;
	//printf("verify :  %f\n", (float)(float)(end - start) / CLOCKS_PER_SEC);
	//testfile << "First update time: " <<time << endl;
	printf("----------------------First update ended--------------------\n");

	struct FAS_Sign* Sign1 = (struct FAS_Sign*)malloc(sizeof(struct FAS_Sign));
	Sign1->E = BN_new();
	Sign1->post_eta = (FAS_BlindProof*)malloc(sizeof(struct FAS_BlindProof));
	Sign1->pre_eta = (FAS_BlindProof*)malloc(sizeof(struct FAS_BlindProof));
	Sign1->sigma = BN_new();
	printf("----------------------sig1 start----------------------\n");
	start = clock();
	Sig(PK, SK, Ms.at(1), Sign1);
	ts.push_back(SK->t_j);
	cout << "SIGN 1 SK->t : "<<SK->t_j << endl;
	end = clock();
	time = (float)(end - start) / CLOCKS_PER_SEC;
	//total_setup += (float)(float)(end - start) / CLOCKS_PER_SEC;
	//printf("sig :  %f\n", (float)(float)(end - start) / CLOCKS_PER_SEC);
	//testfile << "Sign 1 time : " << time << endl;
	printf("----------------------sig1 ended--------------------\n");

	struct FAS_Sign* AggSign = (struct FAS_Sign*)malloc(sizeof(struct FAS_Sign));
	AggSign->E = BN_new();
	AggSign->post_eta = (FAS_BlindProof*)malloc(sizeof(struct FAS_BlindProof));
	AggSign->pre_eta = (FAS_BlindProof*)malloc(sizeof(struct FAS_BlindProof));
	AggSign->sigma = BN_new();
	AggSign = Agg(Sign, Sign1, PK);

	printf("----------------------Second update start--------------------\n");
	start = clock();
	Upd(SK);
	end = clock();
	time = (float)(end - start) / CLOCKS_PER_SEC;
	//total_setup += (float)(float)(end - start) / CLOCKS_PER_SEC;
	//printf("verify :  %f\n", (float)(float)(end - start) / CLOCKS_PER_SEC);
	//testfile << "second update time : " << time << endl;
	printf("----------------------Second update ended--------------------\n");

	struct FAS_Sign* Sign2 = (struct FAS_Sign*)malloc(sizeof(struct FAS_Sign));
	Sign2->E = BN_new();
	Sign2->post_eta = (FAS_BlindProof*)malloc(sizeof(struct FAS_BlindProof));
	Sign2->pre_eta = (FAS_BlindProof*)malloc(sizeof(struct FAS_BlindProof));
	Sign2->sigma = BN_new();
	printf("----------------------sig2 start----------------------\n");
	start = clock();
	Sig(PK, SK, Ms.at(2), Sign2);
	ts.push_back(SK->t_j);
	cout << "SIGN 2 SK->t : " << SK->t_j << endl;
	end = clock();
	time = (float)(end - start) / CLOCKS_PER_SEC;
	//total_setup += (float)(float)(end - start) / CLOCKS_PER_SEC;
	//printf("sig :  %f\n", (float)(float)(end - start) / CLOCKS_PER_SEC);
	//testfile << "Sign 2 time : " << time << endl;
	printf("----------------------sig2 ended--------------------\n");
	AggSign = Agg(AggSign, Sign2, PK);

	printf("----------------------Aggregate verify start--------------------\n");
	start = clock();
	AggVer(PK, AggSign, ts, Ms);
	//AggVer(PK, AggSign, ts, Fake_Ms);
	end = clock();
	time = (float)(end - start) / CLOCKS_PER_SEC;
	//total_setup += (float)(float)(end - start) / CLOCKS_PER_SEC;
	//printf("verify :  %f\n", (float)(float)(end - start) / CLOCKS_PER_SEC);
	//testfile << "Aggregate verify time : " << time<< endl;
	printf("----------------------Aggregate verify ended--------------------\n");
	
	testfile.close();

	
	

	return 0;
}