# fwsec
Code for experiment of [BM],[AR],[IR] and its aggregate version [FAS].



[BM] : Bellare, Mihir, and Sara K. Miner. "A forward-secure digital signature scheme." Annual international cryptology conference. Springer, Berlin, Heidelberg, 1999.

[AR] : Abdalla, Michel, and Leonid Reyzin. "A new forward-secure digital signature scheme." International Conference on the Theory and Application of Cryptology and Information Security. Springer, Berlin, Heidelberg, 2000.

[IR] : Itkis, Gene, and Leonid Reyzin. "Forward-secure signatures with optimal signing and verifying." Annual International Cryptology Conference. Springer, Berlin, Heidelberg, 2001.

[FAS] : Kim, Jihye, and Hyunok Oh. "FAS: Forward secure sequential aggregate signatures for secure logging." Information Sciences 471 (2019): 115-131.

# compile

make BM

make AR

make IR

make BM_FAS

make AR_FAS

# run
./BM 2048 T 256

./AR 2048 T 256

./IR 2048 T 256

./BM_FAS 2048 T 256 n

./AR_FAS 2048 T 256 n

T : total time period, n : the number of signatures
