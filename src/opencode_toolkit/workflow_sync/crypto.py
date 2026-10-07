"""Authenticated encryption for the sync store.

Design constraints, in order of priority:

1. **No third-party runtime dependency.** The default cipher is built from
   ``hashlib``/``hmac`` primitives only, so the offline pack and a clean
   checkout install need nothing from PyPI.
2. **Authenticated.** Ciphertext is authenticated with an encrypt-then-MAC tag
   verified *before* any decryption happens, so tampered data is rejected
   rather than decrypted into garbage.
3. **Modern password-based KDF.** PBKDF2-HMAC-SHA256 with a hard floor of
   100000 iterations and a default of 600000, each payload carrying its own
   random salt.

Default construction (documented precisely, because "it is encrypted" is not a
security argument):

    salt      = os.urandom(16)
    nonce     = os.urandom(16)
    dk        = PBKDF2-HMAC-SHA256(passphrase, salt, iterations, dklen=64)
    enc_key   = dk[0:32]
    mac_key   = dk[32:64]
    keystream = HMAC-SHA256(enc_key, header || nonce || counter_be64) || ...
    ciphertext= plaintext XOR keystream
    tag       = HMAC-SHA256(mac_key, header || salt || nonce || ciphertext)

``header`` is a version byte plus the KDF parameters, so a future format change
is detected before decryption instead of producing corrupt output. When the
optional ``cryptography`` package is present, AES-256-GCM is used instead and
the payload records which construction was used -- the two formats are
distinguishable and both verified with the same interface.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass
from typing import Final

from opencode_toolkit.core.errors import ConfigurationError, EncryptionError

#: Payload format version. Bump when the construction changes.
FORMAT_VERSION: Final = 1

#: PBKDF2 iteration floor. Below this the KDF is refused outright, not warned about.
MIN_ITERATIONS: Final = 100_000
DEFAULT_ITERATIONS: Final = 600_000
SALT_BYTES: Final = 16
NONCE_BYTES: Final = 16
KEY_BYTES: Final = 32
TAG_BYTES: Final = 32
#: Keystream bytes produced by one HMAC-SHA256 invocation (the digest size).
_BLOCK_BYTES: Final = hashlib.sha256().digest_size

#: Construction identifiers stored in the payload header.
CIPHER_AESGCM: Final = "aes-256-gcm"
CIPHER_HMAC_CTR: Final = "hmac-sha256-ctr"

_HEADER_KDF_ALGORITHM: Final = "pbkdf2-hmac-sha256"
#: Domain separation tag for the keystream, so a sealing key can never be
#: confused with a MAC key derived from the same passphrase.
_KEYSTREAM_DOMAIN: Final = b"octk-ks-v1"


def _aescgcm_available() -> bool:
    try:  # pragma: no cover - depends on the host environment
        import cryptography  # noqa: F401
    except ImportError:
        return False
    return True


def available_ciphers() -> tuple[str, ...]:
    """Return the constructions usable in this environment."""
    if _aescgcm_available():  # pragma: no cover - environment dependent
        return (CIPHER_AESGCM, CIPHER_HMAC_CTR)
    return (CIPHER_HMAC_CTR,)


def _keystream(enc_key: bytes, nonce: bytes, length: int) -> bytes:
    """Generate *length* keystream bytes from *enc_key* and *nonce*."""
    if length == 0:
        return b""
    blocks = (length + _BLOCK_BYTES - 1) // _BLOCK_BYTES
    out = bytearray()
    for counter in range(blocks):
        message = _KEYSTREAM_DOMAIN + nonce + counter.to_bytes(8, "big")
        out += hmac.new(enc_key, message, hashlib.sha256).digest()
    return bytes(out[:length])


def _header(version: int, cipher: str, iterations: int) -> bytes:
    """Authenticated header binding the format version and KDF parameters."""
    return (
        b"octk"
        + bytes([version])
        + len(cipher).to_bytes(1, "big")
        + cipher.encode("ascii")
        + iterations.to_bytes(4, "big")
    )


@dataclass(frozen=True, slots=True)
class SealedPayload:
    """A sealed, authenticated blob plus everything needed to verify it."""

    version: int
    cipher: str
    iterations: int
    salt: bytes
    nonce: bytes
    ciphertext: bytes
    tag: bytes

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-safe view (all binary is hex-encoded)."""
        return {
            "format": "opencode-toolkit/sealed",
            "version": self.version,
            "cipher": self.cipher,
            "kdf": _HEADER_KDF_ALGORITHM,
            "iterations": self.iterations,
            "salt": self.salt.hex(),
            "nonce": self.nonce.hex(),
            "ciphertext": self.ciphertext.hex(),
            "tag": self.tag.hex(),
        }

    @classmethod
    def from_dict(cls, document: dict[str, object]) -> SealedPayload:
        """Rebuild a payload from its JSON representation.

        Args:
            document: dict[str, object]: Decoded sealed document as produced by
                :meth:`to_dict`, with every binary field hex-encoded.

        Raises:
            EncryptionError: The document is not an ``opencode-toolkit/sealed``
                blob, or a required field is missing or not valid hex.
        """
        if document.get("format") != "opencode-toolkit/sealed":
            raise EncryptionError(
                "payload is not an opencode-toolkit sealed blob",
                details={"format": document.get("format")},
            )
        try:
            return cls(
                version=int(str(document["version"])),
                cipher=str(document["cipher"]),
                iterations=int(str(document["iterations"])),
                salt=bytes.fromhex(str(document["salt"])),
                nonce=bytes.fromhex(str(document["nonce"])),
                ciphertext=bytes.fromhex(str(document["ciphertext"])),
                tag=bytes.fromhex(str(document["tag"])),
            )
        except (KeyError, ValueError, TypeError) as exc:
            raise EncryptionError(
                f"sealed payload is malformed: {exc}",
                details={"reason": type(exc).__name__},
            ) from exc


def validate_iterations(iterations: int) -> int:
    """Return *iterations*, refusing anything below the enforced floor.

    Args:
        iterations: int: Requested PBKDF2-HMAC-SHA256 iteration count.

    Raises:
        ConfigurationError: *iterations* is below :data:`MIN_ITERATIONS`. The
            floor is never lowered to accommodate a stale config; raise
            ``sync.kdf_iterations`` instead.
    """
    if iterations < MIN_ITERATIONS:
        raise ConfigurationError(
            f"kdf_iterations={iterations} is below the enforced minimum of {MIN_ITERATIONS}",
            details={"minimum": MIN_ITERATIONS, "requested": iterations},
            hint="raise sync.kdf_iterations in the config file rather than lowering the floor",
        )
    return iterations


def seal(
    plaintext: bytes,
    passphrase: str,
    *,
    iterations: int = DEFAULT_ITERATIONS,
    cipher: str | None = None,
) -> SealedPayload:
    """Encrypt and authenticate *plaintext* under *passphrase*.

    Args:
        plaintext: bytes: Content to seal.
        passphrase: str: Passphrase the key is derived from; an empty string is
            rejected because it would make the payload readable by anyone.
        iterations: int: PBKDF2-HMAC-SHA256 cost; must be at least
            :data:`MIN_ITERATIONS`, which raises rather than silently
            downgrading the strength.
        cipher: str | None: Cipher to use. ``None`` selects AES-GCM when the
            optional ``cryptography`` package is importable and the portable
            HMAC-CTR construction otherwise.

    Returns:
        SealedPayload: Ciphertext plus the salt, nonce and authentication tag
            needed to verify and decrypt it. The salt and nonce are freshly
            generated per call, so sealing the same plaintext twice yields
            different output.

    Raises:
        ConfigurationError: The passphrase is empty, *iterations* is below the
            floor, or *cipher* is not supported.
    """
    if not passphrase:
        raise ConfigurationError("an empty passphrase would make the snapshot readable by anyone")
    iterations = validate_iterations(iterations)
    salt = os.urandom(SALT_BYTES)
    nonce = os.urandom(NONCE_BYTES)
    header = _header(FORMAT_VERSION, cipher or CIPHER_HMAC_CTR, iterations)

    if cipher is None:
        cipher = CIPHER_AESGCM if _aescgcm_available() else CIPHER_HMAC_CTR

    if cipher == CIPHER_HMAC_CTR:
        dk = hashlib.pbkdf2_hmac(
            "sha256", passphrase.encode("utf-8"), salt, iterations, dklen=KEY_BYTES * 2
        )
        enc_key, mac_key = dk[:KEY_BYTES], dk[KEY_BYTES:]
        ciphertext = bytes(
            byte ^ key
            for byte, key in zip(plaintext, _keystream(enc_key, nonce, len(plaintext)), strict=True)
        )
        tag = hmac.new(mac_key, header + salt + nonce + ciphertext, hashlib.sha256).digest()
        return SealedPayload(
            version=FORMAT_VERSION,
            cipher=cipher,
            iterations=iterations,
            salt=salt,
            nonce=nonce,
            ciphertext=ciphertext,
            tag=tag,
        )

    if cipher == CIPHER_AESGCM:  # pragma: no cover - optional acceleration path
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        combined = hashlib.pbkdf2_hmac(
            "sha256", passphrase.encode("utf-8"), salt, iterations, dklen=KEY_BYTES
        )
        sealed = AESGCM(combined).encrypt(nonce, plaintext, header + salt + nonce)
        ciphertext, tag = sealed[:-TAG_BYTES], sealed[-TAG_BYTES:]
        # AES-GCM authenticates the tag internally; recomputing it here keeps a
        # single verification code path across both constructions.
        mac_key = hmac.new(combined, b"mac", hashlib.sha256).digest()
        tag = hmac.new(mac_key, header + salt + nonce + ciphertext, hashlib.sha256).digest()
        return SealedPayload(
            version=FORMAT_VERSION,
            cipher=cipher,
            iterations=iterations,
            salt=salt,
            nonce=nonce,
            ciphertext=ciphertext,
            tag=tag,
        )

    raise ConfigurationError(
        f"unsupported cipher: {cipher}", details={"available": list(available_ciphers())}
    )


def open_sealed(payload: SealedPayload, passphrase: str) -> bytes:
    """Verify and decrypt *payload*.

    Raises :class:`EncryptionError` when the passphrase is wrong, the data was
    tampered with, or the format is not recognised. The failure modes are
    intentionally indistinguishable to the caller -- distinguishing them would
    leak information about which guess was closer.

    Args:
        payload: SealedPayload: Sealed document to verify and decrypt.
        passphrase: str: Passphrase the key is derived from; an empty string is
            rejected.

    Raises:
        EncryptionError: The payload version or cipher is unsupported, the
            passphrase is empty, authentication failed, or the payload was
            tampered with. The wrong-passphrase and modified-data cases share one
            message on purpose.
        ConfigurationError: The payload records fewer iterations than
            :data:`MIN_ITERATIONS`, which is refused rather than honoured.
    """
    if payload.version != FORMAT_VERSION:
        raise EncryptionError(
            f"unsupported payload version {payload.version} (this build understands {FORMAT_VERSION})",
            details={"version": payload.version, "supported": FORMAT_VERSION},
        )
    if not passphrase:
        raise EncryptionError("an empty passphrase cannot open a sealed payload")
    validate_iterations(payload.iterations)

    header = _header(payload.version, payload.cipher, payload.iterations)
    dk = hashlib.pbkdf2_hmac(
        "sha256", passphrase.encode("utf-8"), payload.salt, payload.iterations, dklen=KEY_BYTES * 2
    )
    mac_key = dk[KEY_BYTES:]
    expected = hmac.new(
        mac_key, header + payload.salt + payload.nonce + payload.ciphertext, hashlib.sha256
    ).digest()
    if not hmac.compare_digest(expected, payload.tag):
        raise EncryptionError(
            "authentication failed: wrong passphrase or the payload was modified",
            details={"cipher": payload.cipher, "iterations": payload.iterations},
        )

    if payload.cipher == CIPHER_HMAC_CTR:
        enc_key = dk[:KEY_BYTES]
        stream = _keystream(enc_key, payload.nonce, len(payload.ciphertext))
        return bytes(byte ^ key for byte, key in zip(payload.ciphertext, stream, strict=True))

    if payload.cipher == CIPHER_AESGCM:  # pragma: no cover - optional acceleration path
        combined = dk[:KEY_BYTES]
        from cryptography.exceptions import InvalidTag
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        try:
            recovered: bytes = AESGCM(combined).decrypt(
                payload.nonce,
                payload.ciphertext + payload.tag,
                header + payload.salt + payload.nonce,
            )
        except InvalidTag as exc:
            raise EncryptionError(
                "AES-GCM authentication failed: wrong passphrase or the payload was modified"
            ) from exc
        return recovered

    raise EncryptionError(f"unsupported cipher: {payload.cipher}")


def derive_key(passphrase: str, salt: bytes, *, iterations: int, length: int = KEY_BYTES) -> bytes:
    """Expose the KDF so tests can assert the iteration count is really used.

    Args:
        passphrase: str: Passphrase to derive from, encoded as UTF-8.
        salt: bytes: Per-payload salt. It is not generated here: the caller
            supplies the salt recorded in the payload so derivation is
            reproducible.
        iterations: int: PBKDF2-HMAC-SHA256 cost; must be at least
            :data:`MIN_ITERATIONS`.
        length: int: Derived key length in bytes, defaulting to :data:`KEY_BYTES`.

    Raises:
        ConfigurationError: *iterations* is below the enforced floor.
    """
    validate_iterations(iterations)
    return hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, iterations, dklen=length)
