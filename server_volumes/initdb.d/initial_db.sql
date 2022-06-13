USE database;

DROP TABLE IF EXISTS users;

CREATE TABLE users (
    ulid VARCHAR(26) PRIMARY KEY,
    password_hash VARCHAR(60) NOT NULL,
    name VARCHAR(255) NOT NULL,
    email_address VARCHAR(255) NOT NULL
);

INSERT INTO users VALUES (
    '01G5EXPGEREF4Q9Q8NKQPJ3BBT',
    '$2b$12$BYZUTA9z/RBNBaO04lUuEuMEvJnm3hQlnWqu6pUUiZNBIZy9kBtyy',
    'johndoe',
    'johndoe@example.com'
);
