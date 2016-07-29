śarkarā
=======

`Sarkara` is a Post-Quantum cryptography library.


Public-key cryptography
-----------------------

* Authenticated encryption
	+ [x] `newhope-ascon` / `newhope-norx`
* Signatures
	+ [ ] [bliss](http://bliss.di.ens.fr/)
	+ [ ] [NTRUMLS](https://github.com/NTRUOpenSourceProject/NTRUMLS)
	+ [ ] [rlwesig](https://en.wikipedia.org/wiki/Ring_learning_with_errors_signature)
* Key exchange
	+ [x] [newhope](https://github.com/tpoeppelmann/newhope)

Secret-key cryptography
-----------------------

* Authenticated encryption
	+ [x] [norx (if it is CAESAR winner)](https://norx.io/)
	+ [x] [ascon (if it is CAESAR winner)](http://ascon.iaik.tugraz.at/)
* Encryption
	+ [x] [rabbit](http://www.ecrypt.eu.org/stream/rabbitpf.html)
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
* [Experimenting with Post-Quantum Cryptography](https://security.googleblog.com/2016/07/experimenting-with-post-quantum.html)
