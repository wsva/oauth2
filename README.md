OAuth2Service provides OAuth2 services

# generate RSA key
`````
openssl genrsa -out rsa.key 3072
openssl rsa -in rsa.key -pubout -out rsa.pub
`````

# generate Ed25519 key
`````
openssl genpkey -algorithm Ed25519 -out ed25519.key
openssl pkey -in ed25519.key -pubout -out ed25519.pub
`````

Auth.js doesn't support Ed25519.

# DATABASE_URL
`````
DATABASE_URL="oracle://USER:PASSWORD@HOST:PORT/SERVICE_NAME"
DATABASE_URL="postgresql://USER:PASSWORD@HOST:PORT/DATABASE?schema=SCHEMA"
DATABASE_URL="mysql://USER:PASSWORD@HOST:PORT/DATABASE"
DATABASE_URL="file:./dev.db"
DATABASE_URL="sqlserver://HOST:PORT;database=DBNAME;user=USER;password=PASSWORD;trustServerCertificate=true;"
DATABASE_URL="mongodb+srv://USER:PASSWORD@HOST/DATABASE?retryWrites=true&w=majority"
`````

# database (postgresql)
`````
create table oauth2_user (
    user_id       varchar(100) not null primary key,
    nickname      varchar(100),
    username      varchar(100),
    number        varchar(100),
    email         varchar(100) not null,
    password      varchar(100) not null,
    is_superuser  varchar(1)   not null,
    is_staff      varchar(1)   not null,
    is_active     varchar(1)   not null
);

create table oauth2_token (
    access_token  varchar(1000) not null primary key,
    refresh_token varchar(1000) not null,
    client_id     varchar(100)  not null,
    user_id       varchar(100)  not null,
    ip            varchar(100)  not null,
    parent        varchar(1000)
);

create table oauth2_log (
    uuid          varchar(100) not null primary key,
    user_id       varchar(100),
    ip            varchar(100) not null,
    real_ip       varchar(100),
    note          varchar(1000)
);
`````

# kubernetes create secret
`````
kubectl create secret generic aes-key -n als \
  --from-literal=AES_KEY=key
kubectl create secret generic aes-iv -n als \
  --from-literal=AES_IV=iv
`````