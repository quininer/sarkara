śarkarā
=======

Sarkara is a Post-Quantum cryptography library.


Public-key cryptography
-----------------------

* Authenticated encryption
	+ [x] `newhope-ascon`
	+ [x] `newhope-hc128-hmac-blake2`
* Signatures
	+ [ ] [bliss](http://bliss.di.ens.fr/)
* Key exchange
	+ [x] [newhope](https://eprint.iacr.org/2015/1092)

Secret-key cryptography
-----------------------

* Authenticated encryption
	+ [x] [ascon (if it is CAESAR winner)](http://ascon.iaik.tugraz.at/)
	+ [x] `hc128-hmac-blake2`
* Encryption
	+ [x] [hc128](http://www.ecrypt.eu.org/stream/hcpf.html)
* Authentication
	+ [x] `HMAC (nonce variant)`
* Key derivation
	+ [x] [argon2](https://password-hashing.net/)

Low-level functions
-------------------

* Hashing
	+ [x] [blake2](https://blake2.net/)


Reference
---------

* [Breaking Symmetric Cryptosystems using Quantum Period Finding](https://arxiv.org/pdf/1602.05973)
* [Quantum-Secure Message Authentication Codes](http://eprint.iacr.org/2012/606.pdf)
* [Post-quantum security models for authenticated encryption](http://cacr.uwaterloo.ca/techreports/2016/cacr2016-04.pdf)
* [Post-quantum security models for authenticated encryption (talk ppt)](https://pqcrypto2016.jp/data/Soukharev-talk3.pdf)
* [Experimenting with Post-Quantum Cryptography](https://security.googleblog.com/2016/07/experimenting-with-post-quantum.html)
* [The BRUTUS automatic cryptanalytic framework](https://link.springer.com/article/10.1007%2Fs13389-015-0114-1)
