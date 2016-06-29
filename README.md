śarkarā
=======

`Sarkara` is a Post-Quantum cryptography library.


Public-key cryptography
-----------------------

I have not decided to choose which public key cryptography algorithm,
if you have any recommendations, please let me know.

* Authenticated encryption
	`...`
* Signatures
	+ [ ] [bliss](http://bliss.di.ens.fr/)
	+ [ ] [NTRUMLS](https://github.com/NTRUOpenSourceProject/NTRUMLS)
	+ [ ] [rlwesig](https://en.wikipedia.org/wiki/Ring_learning_with_errors_signature)
* Key exchange
	+ [ ] [rlwekex](https://en.wikipedia.org/wiki/Ring_learning_with_errors_key_exchange)
	+ [ ] [newhope](https://github.com/tpoeppelmann/newhope)
	+ [ ] [sidh](https://en.wikipedia.org/wiki/Supersingular_isogeny_key_exchange)

Secret-key cryptography
-----------------------

* Authenticated encryption
	+ [ ] [norx (if it is CAESAR winner)](https://norx.io/)
	+ [ ] [ascon (if it is CAESAR winner)](http://ascon.iaik.tugraz.at/)
* Encryption
	+ [x] [hc128](http://www.ecrypt.eu.org/stream/hcpf.html)
* Authentication
	+ [x] `HMAC (nonce variant)`
* Key derivation
	+ [x] [argon2](https://en.wikipedia.org/wiki/Argon2)

Low-level functions
-------------------

* Hashing
	+ [x] [blake2](https://en.wikipedia.org/wiki/BLAKE\_(hash\_function))


Reference
---------

* [Breaking Symmetric Cryptosystems using Quantum Period Finding](https://arxiv.org/pdf/1602.05973)
* [Quantum-Secure Message Authentication Codes](http://eprint.iacr.org/2012/606.pdf)
* [Post-quantum security models for authenticated encryption](http://cacr.uwaterloo.ca/techreports/2016/cacr2016-04.pdf)
* [Post-quantum security models for authenticated encryption (talk ppt)](https://pqcrypto2016.jp/data/Soukharev-talk3.pdf)
