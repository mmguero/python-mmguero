"""Hashing and key-derivation helpers (SHA-256, SHAKE-256, OpenSSL-compatible EVP_BytesToKey)."""

import hashlib

# EVP_BytesToKey - create key compatible with openssl enc
# reference: https://github.com/openssl/openssl/blob/6f0ac0e2f27d9240516edb9a23b7863e7ad02898/crypto/evp/evp_key.c#L74
#            https://gist.github.com/chrono-meter/d122cbefc6f6248a0af554995f072460
_EVP_KEY_SIZE = 32
_OPENSSL_ENC_MAGIC = b'Salted__'
_PKCS5_SALT_LEN = 8


def evp_bytes_to_key(key_length: int, iv_length: int, md, salt: bytes, data: bytes, count: int = 1) -> (bytes, bytes):
    """EVP_BytesToKey - create a key/IV pair compatible with `openssl enc`.

    Args:
        key_length (int): Desired key length in bytes.
        iv_length (int): Desired IV length in bytes.
        md (callable): Hash constructor (e.g. hashlib.md5) used by the KDF.
        salt (bytes): Salt bytes; must be empty or exactly 8 bytes (PKCS5).
        data (bytes): Password/data bytes to derive the key from.
        count (int, optional): Number of hash iterations per digest block. Defaults to 1.

    Returns:
        tuple[bytes, bytes]: The derived (key, iv).
    """
    assert data
    assert salt == b'' or len(salt) == _PKCS5_SALT_LEN

    md_buf = b''
    key = b''
    iv = b''
    addmd = 0

    while key_length > len(key) or iv_length > len(iv):
        c = md()
        if addmd:
            c.update(md_buf)
        addmd += 1
        c.update(data)
        c.update(salt)
        md_buf = c.digest()
        for i in range(1, count):
            md_buf = md(md_buf)

        md_buf2 = md_buf

        if key_length > len(key):
            key, md_buf2 = key + md_buf2[: key_length - len(key)], md_buf2[key_length - len(key) :]

        if iv_length > len(iv):
            iv = iv + md_buf2[: iv_length - len(iv)]

    return key, iv


# calculate a sha256 hash of a file
def sha256_sum(filename):
    """Calculate a sha256 hash of a file.

    Args:
        filename (str): Path to the file to hash.

    Returns:
        str or None: The SHA-256 hex digest, or None on error.
    """
    try:
        h = hashlib.sha256()
        b = bytearray(64 * 1024)
        mv = memoryview(b)
        with open(filename, 'rb', buffering=0) as f:
            for n in iter(lambda: f.readinto(mv), 0):
                h.update(mv[:n])
        return h.hexdigest()
    except Exception:
        return None


# calculate SHAKE256 hash of a file
def shakey_sum(filename, digest_len=8):
    """Calculate SHAKE256 hash of a file.

    Args:
        filename (str): Path to the file to hash.
        digest_len (int, optional): Digest length in bytes. Defaults to 8.

    Returns:
        str or None: The SHAKE-256 hex digest truncated to `digest_len` bytes, or None on error.
    """
    try:
        with open(filename, 'rb', buffering=0) as f:
            return hashlib.file_digest(f, 'shake_256').hexdigest(digest_len)
    except Exception:
        return None
