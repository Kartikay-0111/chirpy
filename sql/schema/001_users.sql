-- +goose Up
CREATE TABLE users (
    id uuid PRIMARY KEY,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    email TEXT NOT NULL UNIQUE
);

-- +goose Down
DROP TABLE users;