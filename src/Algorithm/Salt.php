<?php

declare(strict_types = 1);

namespace Innmind\Encryption\Algorithm;

use Innmind\Frame\Frame;
use Innmind\Immutable\Str;

enum Salt
{
    case xchacha20poly1305;

    public function new(): string
    {
        return \random_bytes($this->size());
    }

    /**
     * @return Frame<Str>
     */
    public function frame(): Frame
    {
        return match ($this) {
            self::xchacha20poly1305 => Frame::chunk($this->size()),
        };
    }

    /**
     * @return int<1, max>
     */
    private function size(): int
    {
        return match ($this) {
            self::xchacha20poly1305 => \SODIUM_CRYPTO_PWHASH_SALTBYTES,
        };
    }
}
