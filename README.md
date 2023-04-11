# alpn-tls
Experiment using alpn extensions to dynamically serve certificates.

Example HTTP and STREAM module to dynamically set certs
    
Modules add variables:
STREAM:
- challenge_crt
- challenge_key
- production_crt
- production_key
    
HTTP:
- production_crt
- production_key
    
A config to discriminate on alpn extensions is provided to demonstrate negatiating different certicates based on the protocol provided.
    
This could lay the groundwork for a complete TLS-ALPN-01 challenge module(s) to automatically attest challenges and then server dynamically provisioned certificates.

Build:
- Add certificate and key data to the test header files: test/challenge.h, test/production.h
- Build nginx from source:
```
git clone git@github.com:nginx/nginx.git
cd nginx
./auto/configure                   \
  --without-http_fastcgi_module    \
  --without-http_uwsgi_module      \
  --without-http_scgi_module       \
  --with-compat                    \
  --with-stream                    \
  --with-debug                     \
  --with-stream_ssl_module         \
  --with-http_ssl_module           \
  --with-stream_ssl_preread_module \
  --with-http_realip_module        \
  --add-dynamic-module=[CLONE_LOCATION]/alpn-tls
make -j [NUM_CPUS]
```

Test:
- Update and start NGINX with the provided configuration.
- For a "challenge cert":
`openssl s_client -tls1_3 -alpn "acme-tls/1" -showcerts localhost:8443`
- For an L4 "production cert":
`openssl s_client -tls1_3 -showcerts localhost:8443`
- For an L7 "production_cert":
`curl -k -vvv https://localhost:8443`
