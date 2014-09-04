extern void Init();

extern void FPerm(const unsigned char* input, unsigned char* output);
extern int crypto_aead_encrypt(
	unsigned char *c, unsigned long long *clen,
	const unsigned char *m, unsigned long long mlen,
	const unsigned char *ad, unsigned long long adlen,
	const unsigned char *nsec,
	const unsigned char *npub,
	const unsigned char *k
	);
#ifdef EXTRANONCE 
extern int crypto_aead_encrypt_no_nonce(
	unsigned char *c, unsigned long long *clen,
	const unsigned char *m, unsigned long long mlen,
	const unsigned char *ad, unsigned long long adlen,
	const unsigned char *nsec,
	unsigned char *npub,
	const unsigned char *k
	);
#endif

extern
int crypto_aead_decrypt(
unsigned char *m, unsigned long long *mlen,
unsigned char *nsec,
const unsigned char *c, unsigned long long clen,
const unsigned char *ad, unsigned long long adlen,
const unsigned char *npub,
const unsigned char *k
);

extern  int key_bytes;
extern  int nonce_bytes;
extern  int tag_bytes;
