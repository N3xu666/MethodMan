# masking-dict.test.ps1
# Test dictionary with FAKE values - safe to commit.
# Structure mirrors the real masking-dict.ps1.
#
# Used by tests/run-tests.ps1 to verify mask.ps1 behavior
# without exposing real secrets.
#
# NOTE: combo and password keys are DISTINCT so that combo
# replacement is tested honestly (would not be tested if
# password were a substring of combo).

$replacements = @{
    # === COMBO CREDENTIALS ===
    'combo_user:combo_pass_xyz' = 'combo_user:<PASSWORD>'

    # === FLAGS ===
    'ff7cb55f76acbd3560efe4c1a19ecfb5' = '<USER_FLAG>'
    'c5a8f8dc9f8bca0c1c2e3d4e5f6a7b8c' = '<ROOT_FLAG>'
    'd1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6' = '<SYSTEM_FLAG>'

    # === PASSWORDS ===
    'standalone_pw_abc' = '<PASSWORD>'

    # === HASHES ===
    '$2y$10$abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLM' = '<BCRYPT_HASH>'
    '$5$rounds=5000$saltsaltsalt$hashhashhashhashhashhashhashhashhashhashhash' = '<SHA256_HASH>'
    '*ABCDEF1234567890ABCDEF1234567890ABCDEF12' = '<MYSQL_HASH>'
    '5f4dcc3b5aa765d61d8327deb882cf99' = '<MD5_HASH>'

    # === TOKENS ===
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456' = '<TOKEN>'

    # === SESSION IDS ===
    'sess_abc123def456ghi789jkl012mno345pqr' = '<SESSION_ID>'

    # === SSH KEYS ===
    'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDtesttesttest' = '<SSH_KEY>'

    # === SERIALS ===
    'SN-FAKE12345-ABCDE' = '<SERIAL>'

    # === BOOKING REFS ===
    'BR-2026-1234-XYZ' = '<BOOKING_REF>'

    # === SECURITY KEYS ===
    'sec_key_0123456789abcdef0123456789abcdef' = '<SECURITY_KEY>'
}

