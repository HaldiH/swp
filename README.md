# server
A secured password manager using SQLite to store passwords and AES to encrypt each row

To generate the self-signed certificates, use OpenSSL:

```bash
openssl dhparam -out dh.pem 4096 # or 2048 for faster generation
openssl req -newkey rsa:4096 -nodes -keyout key.pem -x509 -days 10000 -out cert.pem -subj "/C=FR/ST=H2/L=Annecy/O=HeavyEyelid/CN=www.example.com"
```