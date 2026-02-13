-- Create the schema_migrations table (required by golang-migrate)
-- Try to create with current user permissions
CREATE TABLE IF NOT EXISTS schema_migrations (
    version bigint NOT NULL PRIMARY KEY,
    dirty boolean NOT NULL
);

-- Manually run the account and user migrations directly
CREATE TABLE IF NOT EXISTS accounts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Mark migrations as applied
INSERT INTO schema_migrations (version, dirty) VALUES (1, false) ON CONFLICT (version) DO NOTHING;
INSERT INTO schema_migrations (version, dirty) VALUES (2, false) ON CONFLICT (version) DO NOTHING;