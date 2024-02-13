openssl version
# OpenSSL 1.1.1f  31 Mar 2020
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
openssl pkcs12 -export -out key.p12 -inkey key.pem -in cert.pem
openssl pkcs12 -in key.p12 --info 1>/dev/null
# Enter Import Password:
# MAC: sha1, Iteration 2048
# MAC length: 20, salt length: 8
# PKCS7 Encrypted data: pbeWithSHA1And40BitRC2-CBC, Iteration 2048
