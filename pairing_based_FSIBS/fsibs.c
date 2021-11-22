#include <pbc.h>
#include <stdio.h>
#include <math.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

//#define MAX_DEPTH 10
//#define MAX_STRLEN 50
int k, T, n, m;

typedef struct public_parameter {
	element_t g, g1, g2, g3;
	//element_t h[MAX_DEPTH];	
} public_parameter;

typedef struct time_period {
	int len;
	int* t;
} time_period;

typedef struct K {
	int i;
	element_t *k;
} K;

typedef struct MSK {
	time_period t;
	K *msk;
} MSK;

typedef struct VK {
	element_t g;
	element_t V;
	element_t *d;
	element_t *h;
	element_t *f;
} VK;

typedef struct ID {
//	int len;
	int *id;
} ID;

typedef struct SK {
	time_period t;
	K *sk;
	ID id;
} SK;

typedef struct signature {
	ID id;
	time_period t;
	element_t *s;
} signature;

void CopyTimePeriod(time_period *out, time_period *in) {
	out->len = in->len;
	out->t = (int*)malloc(sizeof(int)*out->len);
	int i = 0;
	for(; i<in->len;i++){
		out->t[i] = in->t[i];
	}
}

void CopyID(ID *out, ID *in) {
	for ( int i = 0; i < n; i++ ) {
		out->id[i] = in->id[i];
	}
}

void Sibling(time_period *out, int i, time_period* t){
	int j = 0;
	if(i == (T+1)){
		CopyTimePeriod(out, t);
		return;
	}
	else if((i <= T) && (t->t[i-1] == 1)){
		out->len = 0;
		return;
	}
	else if((i <= T) && (t->t[i-1] == 0)){
		out->len = i;
		out->t = (int*)malloc(sizeof(int)*i);
		for(; j < i - 1; j++) {
			out->t[j] = t->t[j];
		}
		out->t[i-1] = 1;
		return;
	}
}


//typedef struct decrypt_key_ID {
//	ID I;
//	element_t a0, a1;
//	element_t b[MAX_DEPTH];			///////
//} d_ID;

//typedef struct ciphertext {
//	element_t A, B, C;
//} CT;

void PKGKeyGen(public_parameter *params, MSK *MSK1, VK *vk, pairing_t pairing){
	// setting vk
	element_t v;
	element_init_Zr(v, pairing);
	element_random(v);								// pick random v from Zp
	element_init_G1(vk->g, pairing);
	element_random(vk->g);							// pick random g from G1
	element_init_GT(vk->V, pairing);
	pairing_apply(vk->V, vk->g, vk->g, pairing);		// V = e(g,g)^v
	element_pow_zn(vk->V, vk->V, v);
	int i = 0;
	for(;i<=T;i++){									// random h0, ...., hl
		element_init_G1(vk->h[i], pairing);
		element_random(vk->h[i]);
	}
	element_init_G1(vk->h[T+1], pairing);
 	element_set1(vk->h[T+1]);
	for(i = 0; i <= n; i++ ){						// random d0, ..., dn
		element_init_G1(vk->d[i], pairing);
		element_random(vk->d[i]);
	}
	for(i = 0; i <= m; i++ ){						// random f0, ..., fm
		element_init_G1(vk->f[i], pairing);
		element_random(vk->f[i]);
	}

	// seting MSK
	time_period t;
	t.len = T;
	t.t = (int*)malloc(sizeof(int)*T);
	for(i = 0; i < T-1; i++) {						// we set t = 0^{l-1}1
		t.t[i] = 0;
	}
	t.t[T-1] = 1;
	
	time_period *key = (time_period*)malloc(sizeof(time_period)*(T+1));
	for(i = 1; i <= T+1; i++) {
		Sibling(key+(i-1), i, &t);
	}
	CopyTimePeriod(&(MSK1->t), &t);					// MSK t setting

	element_t temp;
	element_t temp1;
	element_init_G1(temp, pairing);
	element_init_G1(temp1, pairing);
	element_t r;
	element_init_Zr(r, pairing);

	//MSK1->msk[i-1].k = (element_t*)malloc(sizeof(element_t)*(T-i+2)); // K max = T+2 so i =1, msk[0].k size = T+2
	for( i = 1; i<= T; i++ ){
		MSK1->msk[i-1].k = (element_t*)malloc(sizeof(element_t)*(T-i+3));
		for(int j = 0; j<T-i+3;j++ ){
			element_init_G1(MSK1->msk[i-1].k[j], pairing);
		}
		if(key[i-1].len == 0){
			MSK1->msk[i-1].k = NULL;
		}
		else{
			element_random(r);
			element_set(temp, vk->h[0]);
			for(int j = 1; j<=i; j++){
				if(key[i].len){
					element_mul(temp, temp, vk->h[j]);
				}
			}
			element_pow_zn(temp, temp, r);						// temp = (h...)^r
			element_pow_zn(temp1, vk->g, v);					// temp1 = g^v
			element_mul(MSK1->msk[i-1].k[0], temp, temp1);	// K[0] = temp * temp1
			element_pow_zn(MSK1->msk[i-1].k[1], vk->g, r);			// K[1] = g^r
			for(int j = 0; j < T-i; j++){
				element_pow_zn(MSK1->msk[i-1].k[j+2], vk->h[j+1],r);// K[j+2] = h_{j+1}^r
			}
		}
	}
	element_random(r);
	element_mul(temp, vk->h[0], vk->h[T]);
	element_pow_zn(temp, temp, r);

	MSK1->msk[T].k = (element_t*)malloc(sizeof(element_t)*2);
 	element_init_G1(MSK1->msk[T].k[0], pairing);
 	element_init_G1(MSK1->msk[T].k[1], pairing);

	element_mul(MSK1->msk[T].k[0], temp, temp1);
	element_pow_zn(MSK1->msk[T].k[1], vk->g, r);

}

void KeyIssue(SK *SK1, MSK *MSK1, ID *id, VK *vk, pairing_t pairing){
	element_t temp;
	element_init_G1(temp, pairing);
	element_set(temp, vk->h[0]);
	element_t temp1;
	element_init_G1(temp1, pairing);
	element_set(temp1, vk->d[0]);
	CopyTimePeriod(&(SK1->t), &(MSK1->t));			// SK->t = MSK->t
	CopyID(&(SK1->id), id);

	element_t dum;
 	element_init_G1(dum, pairing);
 	element_set(dum, vk->h[1]);
 	element_mul(dum, dum, temp);
 	// i = 1~T+1 and msk[i-1].k has to be not NULL
 	for(int i = 1; i <= T+1 && MSK1->msk[i-1].k != NULL; i++){					// setting K_i
		element_t r;
		element_init_Zr(r, pairing);
		element_random(r);							// random r_j
		element_t u;
		element_init_Zr(u, pairing);
		element_random(u);							// random u_j
		SK1->sk[i-1].i = i;
		for(int j = 1; j <= i; j++) {
			if(MSK1->t.len){
				element_mul(temp, temp, vk->h[j]);
			}
		}
		element_pow_zn(temp, temp, r);				// (h....)^r
		for(int j = 1; j < n; j++) {
			if(id->id[j-1]){
				element_mul(temp1, temp1, vk->d[j]);
			}
		}
		element_pow_zn(temp1, temp1, u);			// (d....)^u
		element_mul(temp, temp, MSK1->msk[i-1].k[0]);		// temp = temp * a0
		element_mul(SK1->sk[i-1].k[0], temp, temp1);		// a0 * (h...)^r * (d...)^u

		element_pow_zn(temp, vk->g, r);				// temp = g^r
		element_mul(SK1->sk[i-1].k[1], temp, MSK1->msk[i-1].k[1]);		// a1 * g^r

		element_pow_zn(SK1->sk[i-1].k[2], vk->g, u);						// g^u

		for(int j = i+1; j <= T; j++) {
			element_pow_zn(temp, vk->h[j], r);							// (h_{j+1})^r
			element_mul(SK1->sk[i-1].k[2+j-i], temp, MSK1->msk[i-1].k[1+j-i]);		// (b_{j+1}) * (h_{j+1})^r
		}
	}

}

void Sign(signature *sign, SK *sk, ID *msg, VK *vk, pairing_t pairing) {
	sign->s = (element_t*)malloc(sizeof(element_t)*4);
	sign->id.id = (int*)malloc(sizeof(int)*m);
	CopyID(&(sign->id), &(sk->id));
	CopyTimePeriod(&(sign->t), &(sk->t));


}

//void Copy_ID(ID *to, ID *from){
//	to->depth = from->depth;
//	to->id = from->id;
//}
//
//void Construct_ID(ID *t, int d, char** str, pairing_t pairing){
//	t->depth = d;
//	t->id = (element_t*)malloc(sizeof(element_t)*d);
//	for (int i = 0; i < d; i++ ) {
//		element_init_Zr(t->id[i], pairing);
//		element_from_hash(t->id[i], str[i], strlen(str[i]));
//	}
//}
//
//void Construct_d_ID(d_ID *t_d_ID, pairing_t pairing){
//	element_init_G1(t_d_ID->a0, pairing);
//	element_init_G1(t_d_ID->a1, pairing);
//	for ( int i = 0; i < MAX_DEPTH - t_d_ID->I.depth; i++ ){
//		element_init_G1(t_d_ID->b[i], pairing);
//	}
//}
//
//void Construct_CT(CT *ct, pairing_t pairing){
//	element_init_GT(ct->A, pairing);
//	element_init_G1(ct->B, pairing);
//	element_init_G1(ct->C, pairing);
//}
//
//void Setup(public_parameter *params, element_t msk, pairing_t pairing) {
//	element_t alpha;
//	element_init_Zr(alpha, pairing);
//	element_random(alpha);	// pick random alpha from Zp.
//	element_init_G1(params->g, pairing);	
//	element_random(params->g);
//	element_init_G1(params->g1, pairing);
//	element_pow_zn(params->g1, params->g, alpha);// g1 = g^alpha;
//	element_init_G1(params->g2, pairing);
//	element_random(params->g2);
//	element_init_G1(params->g3, pairing);
//	element_random(params->g3);
//	for (int i = 0; i < MAX_DEPTH; i++ ) {
//		element_init_G1(params->h[i], pairing);
//		element_random(params->h[i]);
//	}
//	element_init_G1(msk, pairing);
//	element_pow_zn(msk, params->g2, alpha);// msk = g2^alpha
//}
//
//void KeyGen(d_ID* old, d_ID* new, public_parameter *params, pairing_t pairing) {
//	element_t random_t;
//	element_init_Zr(random_t, pairing);
//	element_random(random_t);
//	element_t temp1;
//	element_init_G1(temp1, pairing);
//	element_t temp2;
//	element_init_G1(temp2, pairing);
//	element_pow_zn(temp1, old->b[0], new->I.id[new->I.depth - 1]); //b[0] := b_k
//	element_mul(temp2, old->a0, temp1);
//	element_t temp3;
//	element_init_G1(temp3, pairing);
//	element_set1(temp3);
//	for ( int i = 0; i < new->I.depth; i++ ){
//		element_pow_zn(temp1, params->h[i], new->I.id[i]);
//		element_mul(temp3, temp1, temp3);
//	}
//	element_mul(temp3, temp3, params->g3);
//	element_pow_zn(temp3, temp3, random_t);
//	element_mul(new->a0, temp3, temp2);		// new.a0
//
//	element_pow_zn(temp1, params->g, random_t);
//	element_mul(new->a1, old->a1, temp1);		// new.a1
//
//	for ( int i = new->I.depth; i < MAX_DEPTH; i++ ){		// new.b_l
//		element_pow_zn(temp1, params->h[i], random_t);
//		element_mul(new->b[i - new->I.depth], temp1, old->b[i - new->I.depth + 1]);
//	}
//}
//
//void Encrypt(ID* pk, char* msg, CT* ct, public_parameter* params, pairing_t pairing) {
//	element_t s;					// pick random s from Zp
//	element_init_Zr(s, pairing);
//	element_random(s);
//
//	element_t temp1;
//	element_init_GT(temp1, pairing);
//	element_from_bytes(temp1, msg);
//
//	element_t temp2;
//	element_init_GT(temp2, pairing);
//	pairing_apply(temp2, params->g1, params->g2, pairing);
//	element_pow_zn(temp2, temp2, s);
//
//	element_mul(ct->A, temp2, temp1);		// CT->A
//
//	element_pow_zn(ct->B, params->g, s);	// CT->B
//
//	element_t temp3, temp4;
//	element_init_G1(temp3, pairing);
//	element_init_G1(temp4, pairing);
//	element_set1(temp4);
//	for (int i = 0 ; i < pk->depth; i++ ) {
//		element_pow_zn(temp3, params->h[i], pk->id[i]);
//		element_mul(temp4, temp4, temp3);
//	}
//	element_mul(temp4, temp4, params->g3);
//	element_pow_zn(ct->C, temp4, s);		// CT->C
//}
//
//void Decrypt(d_ID* sk, CT* ct, pairing_t pairing) {
//	element_t temp1, temp2;
//	element_init_GT(temp1, pairing);
//	element_init_GT(temp2, pairing);
//	pairing_apply(temp1, sk->a1, ct->C, pairing);
//	pairing_apply(temp2, ct->B, sk->a0, pairing);
//	element_mul(temp1, ct->A, temp1);
//	element_div(temp1, temp1, temp2);
//
//	int len = element_length_in_bytes(temp1);
//	char* msg = (char*)malloc(sizeof(char)*(len+1));
//	msg[len] = '\0';
//	element_to_bytes(msg, temp1);
//	printf(msg);
//	printf("\n");
//}

int main(int argc, char* argv[]) {
// parameter : k, T, n, m (n : user space bit), (m : message space bit)
// T : 주기의 지수부!!! (ex: 32000 -> 15)

	pairing_t pairing;
	char param[1024];
	size_t count = fread(param, 1, 1024, stdin);
	if (!count) pbc_die("input error");
	pairing_init_set_buf(pairing, param, count);
	 
	//parameter setting
	if(argc != 5){
		printf("arguments needed : k, T, n, m (n : user space bit), (m : message space bit)\n");
		return 0;
	}
	k = atoi(argv[1]);
	T = atoi(argv[2]);
	n = atoi(argv[3]);
	m = atoi(argv[4]);

	public_parameter *params;
	params = (public_parameter*)malloc(sizeof(public_parameter));


	// PKGKeyGen : To generate MSK_1 
	MSK *MSK1;
	VK *vk;
	MSK1 = (MSK*)malloc(sizeof(MSK));
	MSK1->msk = (element_t*)malloc(sizeof(element_t)*(T+1));
	vk = (VK*)malloc(sizeof(VK));
	vk->h = (element_t*)malloc(sizeof(element_t)*(T+2));
	vk->d = (element_t*)malloc(sizeof(element_t)*(n+1));
	vk->f = (element_t*)malloc(sizeof(element_t)*(m+1));
	PKGKeyGen(params, MSK1, vk, pairing);

	// KeyIssue : To generate SK_{t,ID} using MSK_t and ID
	ID id;
	id.id = (int*)malloc(sizeof(int)*n);
	srand(time(NULL));
	printf("ID : ");
	for (int i = 0; i < n; i++){
		id.id[i] = rand()%2;
		printf("%d", id.id[i]);
	}
	printf("\n");
	SK* SK1 = (SK*)malloc(sizeof(SK));
	SK1->sk = (K*)malloc(sizeof(K)*(T+1));
	SK1->id.id = (int*)malloc(sizeof(int)*n);
	for (int i = 0; i < T+1; i++){
		SK1->sk[i].k = (element_t*)malloc(sizeof(element_t)*(3+T-i));
		for(int j=0;j<3+T-i;j++){
			element_init_G1(SK1->sk[i].k[j], pairing);
		}
	}
	KeyIssue(SK1, MSK1, &id, vk, pairing);

	// Sign : To generate signature using SK_{t,ID}
	ID message;
	message.id = (int*)malloc(sizeof(int)*m);
	printf("message : ");
	for (int i = 0; i < m; i++) {
		message.id[i] = rand()%2;
		printf("%d", message.id[i]);
	}
	printf("\n");
	signature sign;
	Sign(&sign, SK1, &message, vk, pairing);

	
	///////////////////////////// hibe ////////////////////////////
//	Setup(params, msk, pairing); 
//
//	// To generate a private key d_ID of root
//	d_ID *d_root;
//	d_root = (d_ID*)malloc(sizeof(d_ID));
//	d_root->I.depth = 0;
//	Construct_d_ID(d_root, pairing);
//	element_t r;
//	element_init_Zr(r, pairing);
//	element_random(r);
//	element_t temp1;
//	element_init_G1(temp1, pairing);
//	element_pow_zn(temp1, params->g3, r);
//	element_mul(d_root->a0, msk, temp1);			// a0 = g2^alpha * (h1^I1)^r)
//	element_pow_zn(d_root->a1, params->g, r);
//	for( int i = 0; i < MAX_DEPTH ; i++ ) {
//		element_pow_zn(d_root->b[i], params->h[i+d_root->I.depth], r);
//	}
//
//	// KeyGen : To generate ID_k from given ID_(k-1)
//	// To generate a root ID.
//	ID* univ;
//	univ = (ID*)malloc(sizeof(ID));
//	char** str_univ;
//	str_univ = (char**)malloc(sizeof(char*)*MAX_DEPTH);
//	for ( int i = 0; i < MAX_DEPTH; i++ ) {
//		*(str_univ+i) = (char*)malloc(sizeof(char)*MAX_STRLEN);
//		memset(*(str_univ+i), 0, MAX_STRLEN);
//	}
//	strncpy(*str_univ, "hanyang_univ", strlen("hanyang_univ"));
//	Construct_ID(univ, 1, str_univ, pairing);
//
//	// To generate a private key d_ID of depth 1 "univ" 
//	d_ID *d_univ;
//	d_univ = (d_ID*)malloc(sizeof(d_ID));
//	Copy_ID(&(d_univ->I), univ);
//	Construct_d_ID(d_univ, pairing);
//	KeyGen(d_root, d_univ, params, pairing);
//
//	// KeyGen : To generate ID_k from given ID_(k-1)
//	ID *new;
//	new = (ID*)malloc(sizeof(ID));
//	char** str_new;
//	str_new = (char**)malloc(sizeof(char*)*MAX_DEPTH);
//	for ( int i = 0; i < MAX_DEPTH; i++ ) {
//		*(str_new+i) = (char*)malloc(sizeof(char)*MAX_STRLEN);
//		memset(*(str_new+i), 0, MAX_STRLEN);
//	}
//	strncpy(*str_new, "hanyang_univ", strlen("hanyang_univ"));
//	strncpy(*(str_new + 1), "information_system", strlen("information_system"));
//	Construct_ID(new, 2, str_new, pairing);
//	d_ID *d_new;
//	d_new = (d_ID*)malloc(sizeof(d_ID));
//	Copy_ID(&(d_new->I), new);
//	Construct_d_ID(d_new, pairing);
//	KeyGen(d_univ, d_new, params, pairing);
//
//	// Encrypt : To encrypt a message M under the public key ID
//	CT *ct;
//	ct = (CT*)malloc(sizeof(CT));
//	Construct_CT(ct, pairing);
//	char* msg = "Hello World!";
//	Encrypt(new, msg, ct, params, pairing);
//
//	// Decrypt : To decrypt a given CT using private key d_id
//	Decrypt(d_new, ct, pairing);
//
	return 0;
}
