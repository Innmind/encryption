<?php

declare(strict_types = 1);

namespace Innmind\Encryption\Algorithm;

use Innmind\Encryption\{
    DerivationKey,
    Password,
    Sensitivity,
};

/**
 * @psalm-immutable
 */
enum Hash
{
    case xchacha20poly1305;

    public function size(): int
    {
        return match ($this) {
            self::xchacha20poly1305 => \SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES,
        };
    }

    public function key(
        Password $password,
        string $salt,
        Sensitivity $sensitivity,
    ): DerivationKey {
        return new DerivationKey(match ($this) {
            self::xchacha20poly1305 => \sodium_crypto_pwhash(
                $this->size(),
                $password->unwrap(),
                $salt,
                $sensitivity->operations(),
                $sensitivity->memory(),
                \SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13,
            ),
        });
    }
}
