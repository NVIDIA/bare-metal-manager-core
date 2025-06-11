# localhost certs

This is a CA cert (`ca.crt`, `ca.key`), tls server cert (`localhost.crt`, `localhost.key`), and
client cert (`client.crt`, `client.key`), which work together for localhost as the common name.
There's nothing carbide-specific about this, it's just a set of certs that work if you put the
ca.crt in your trust store.

The cert for localhost also has 127.0.0.1 as an IP SAN, so it can be used for connections for both
"localhost" and "127.0.0.1".

If they expire, use `rm -f *.crt *.key && ./gen-certs.sh` to regenerate them.
