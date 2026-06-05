-- name: UpdateUser :one
UPDATE users
SET
    email = COALESCE(sqlc.narg(email), email),
    hashed_password = COALESCE(sqlc.narg(hashed_password), hashed_password),
    updated_at = NOW()
WHERE id = sqlc.arg(id)
RETURNING *;