śarkarā
=======

Sarkara is a cryptography library like Sodium. But use only Post-Quantum cryptography algorithms.


Public-key cryptography
-----------------------

* Authenticated encryption
	`rlwekex-norx`
* Signatures
	[bliss](http://bliss.di.ens.fr/)
* Key exchange
	[rlwekex](https://en.wikipedia.org/wiki/Ring_learning_with_errors_key_exchange)

Secret-key cryptography
-----------------------

* Authenticated encryption
	[norx (if it is CAESAR winner)](https://norx.io/)
* Encryption
	[hc256](https://en.wikipedia.org/wiki/HC-256)
* Authentication
	`HMAC-blake2 (nonce variant)`
* Key derivation
	[argon2](https://en.wikipedia.org/wiki/Argon2)

Low-level functions
-------------------

* Hashing
	[blake2](https://en.wikipedia.org/wiki/BLAKE\_(hash\_function))


Reference
---------

* [Breaking Symmetric Cryptosystems using Quantum Period Finding](https://arxiv.org/pdf/1602.05973)
* [Quantum-Secure Message Authentication Codes](http://eprint.iacr.org/2012/606.pdf)
* [Post-quantum security models for authenticated encryption](http://cacr.uwaterloo.ca/techreports/2016/cacr2016-04.pdf)
* [Post-quantum security models for authenticated encryption (talk ppt)](https://pqcrypto2016.jp/data/Soukharev-talk3.pdf)
