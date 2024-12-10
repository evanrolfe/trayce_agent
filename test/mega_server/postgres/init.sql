CREATE TABLE things (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    quantity INTEGER NOT NULL DEFAULT 0,
    price NUMERIC(10,2) NOT NULL DEFAULT 0.00,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

INSERT INTO things (name, quantity, price)
VALUES
    ('Widget', 5, 19.99),
    ('Gadget', 10, 5.49),
    ('Doodah', 3, 99.99);
