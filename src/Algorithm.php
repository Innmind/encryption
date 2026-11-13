<?php

declare(strict_types = 1);

namespace Innmind\Encryption;

/**
 * @psalm-immutable
 */
enum Algorithm
{
    case xchacha20poly1305;

    public function hash(): Algorithm\Hash
    {
        return match ($this) {
            self::xchacha20poly1305 => Algorithm\Hash::xchacha20poly1305,
        };
    }

    public function salt(): Algorithm\Salt
    {
        return match ($this) {
            self::xchacha20poly1305 => Algorithm\Salt::xchacha20poly1305,
        };
    }
}
