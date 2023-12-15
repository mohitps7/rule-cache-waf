# Rule-Cache-WAF

## Origin Server
A sample origin server exists in `/origin` that will serve https requests on localhost:9000.

To run:

1. Generate a self-signed SSL certificate for localhost.

```
openssl genrsa -out localhost.key 2048
openssl req -new -key localhost.key -out localhost.csr
openssl x509 -req -days 365 -in localhost.csr -signkey localhost.key -out localhost.crt
```

2. Run `go run https_server.go`.

## WAF

To run the WAF, an existing `config.json` has been supplied in `/waf`. 
Blocking rules are corresponded by their IDs:
```
    0 - IP Fingerprinting
    1 - Header Fingerprinting
    2 - Pretty JSON Fingerprinting
    3 - TLS Fingerprinting
```

1. Generate a self-signed SSL certificate for localhost.

```
openssl genrsa -out localhost.key 2048
openssl req -new -key localhost.key -out localhost.csr
openssl x509 -req -days 365 -in localhost.csr -signkey localhost.key -out localhost.crt
```

2. Run `go run .`