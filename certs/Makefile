ed25519: ed25519-key ed25519-csr sign-ed25519-csr pk12-ed25519

rsa4096: rsa4096-key rsa4096-csr sign-rsa4096-csr pk12-rsa4096

clean:
	rm rustcryp.to.key rustcryp.to.csr rustcryp.to.crt

## Server Cert Keys

ed25519-key:
	openssl genpkey -algorithm ED25519 > rustcryp.to.ed25519.key

rsa4096-key:
	openssl genrsa -out rustcryp.to.rsa4096.key 4096

## CA

ca-rsa4096-key:
	openssl genrsa -out ca.rsa4096.key 4096

ca-rsa4096-crt:	ca-rsa4096-key
	openssl req -x509 -new -nodes -key ca.rsa4096.key -out ca.rsa4096.crt \
		-subj /C=XX/ST=YY/L=Antarctica/O=RustCrypto/OU=Contributors/CN=ca.rustcryp.to

## CSR

ed25519-csr:
	openssl req -new -out rustcryp.to.ed25519.csr -key rustcryp.to.ed25519.key -config openssl.cnf

rsa4096-csr: rsa4096-key
	openssl req -new -out rustcryp.to.rsa4096.csr -key rustcryp.to.rsa4096.key -config cert.cnf


## Sign PKCS10 CA certified

ca-sign-rsa4096-csr:
	openssl x509 -req \
		-in rustcryp.to.rsa4096.csr \
		-out rustcryp.to.rsa4096.ca_signed.crt \
		-CA ca.rsa4096.crt \
		-CAkey ca.rsa4096.key \
		-CAcreateserial  \
		-days 30 \
		-extensions v3_end \
		-extfile openssl.cnf

## Sign PKCS10 self-certified

sign-ed25591-csr:
	openssl x509 -req -days 30 -in rustcryp.to.ed25519.csr -signkey rustcryp.to.ed25519.key -out rustcryp.to.ed25519.crt

sign-rsa4096-csr:
	openssl x509 -req -days 30 -in rustcryp.to.rsa4096csr -signkey rustcryp.to.rsa4096.key -out rustcryp.to.rsa4096.crt

## Export PKCS12

pk12-ed25519:
	openssl pkcs12 -export -out rustcryp.to.ed25519.pfx -inkey rustcryp.to.ed25519.key -in rustcryp.to.ed25519.crt -passout pass:test

pk12-rsa4096:
	openssl pkcs12 -export -out rustcryp.to.rsa4096.pfx -inkey rustcryp.to.rsa4096.key -in rustcryp.to.rsa4096.crt -passout pass:test

