CREATE TABLE things (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name TEXT NOT NULL,
    quantity INT NOT NULL DEFAULT 0,
    price DECIMAL(10,2) NOT NULL DEFAULT 0.00,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO things (name, quantity, price)
VALUES
    ('Widget', 5, 19.99),
    ('Gadget', 10, 5.49),
    ('Doodah', 3, 99.99);
