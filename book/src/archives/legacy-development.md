# Legacy development workflow
### Pre-reqs
  * Kea
  * Rust
  * Postgresql
  * boost-libs
  * gnu-c++

### PostgreSQL

You can run PostgreSQL locally if you wish.  We expect your unix username to be
able to create/delete databases for tests, or have a single database to run the
code in.

1. ```sudo -iu postgres```
2. ```initdb --locale=en_US.UTF-8 -E UTF8 -D /var/lib/postgres/data```
3. ```createuser --interactive carbide_development (answer yes to super user)```
4. ```createdb carbide_development```
5. ```cargo run --bin carbide-api migrate```

### Kea

1. Install Kea from package manager or compile from source
2.```cp dev/kea-dhcp4.conf.example dev/kea-dhcp4.conf```
  *Make sure to change the listen interface to reflect your system.*
