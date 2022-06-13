USE database;

CREATE TABLE users (
    ulid VARCHAR(26) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    email_address VARCHAR(255) NOT NULL
);

INSERT INTO users VALUES (
    '01G5EXPGEREF4Q9Q8NKQPJ3BBT',
    'johndoe',
    'johndoe@example.com'
);
