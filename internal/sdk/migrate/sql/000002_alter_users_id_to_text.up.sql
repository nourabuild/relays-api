ALTER TABLE todos.users
    ALTER COLUMN id DROP IDENTITY;

ALTER TABLE todos.users
    ALTER COLUMN id TYPE TEXT
    USING id::text;
