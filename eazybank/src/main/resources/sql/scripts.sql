CREATE TABLE users(
                      username varchar(50) NOT NULL PRIMARY KEY,
                      password varchar(500) NOT NULL,
                      enabled boolean NOT NULL
);

CREATE TABLE authorities (
                             username varchar(50) NOT NULL,
                             authority varchar(50) NOT NULL,
                             CONSTRAINT fk_authorities_users FOREIGN KEY(username) REFERENCES users(username)
);

CREATE UNIQUE INDEX ix_auth_username ON
    authorities (
                 username,
                 authority
        );

INSERT
IGNORE
INTO
	users
VALUES (
	'user',
	'{noop}EazyBytes@12345',
	'1'
);

INSERT
IGNORE
INTO
	authorities
VALUES (
	'user',
	'read'
);

INSERT
IGNORE
INTO
	users
VALUES (
	'admin',
	'{bcrypt}$2a$12$88.f6upbBvy0okEa7OfHFuorV29qeK.sVbB9VQ6J6dWM1bW6Qef8m',
	'1'
);

INSERT
IGNORE
INTO
	authorities
VALUES (
	'admin',
	'admin'
);
