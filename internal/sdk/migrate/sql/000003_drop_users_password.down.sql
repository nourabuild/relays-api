ALTER TABLE todos.users
    ADD COLUMN password TEXT NOT NULL DEFAULT '';

ALTER TABLE todos.users
    ALTER COLUMN password DROP DEFAULT;
