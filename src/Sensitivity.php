<?php

declare(strict_types = 1);

namespace Innmind\Encryption;

use Innmind\Frame\Frame;

/**
 * @psalm-immutable
 */
enum Sensitivity
{
    case low;
    case moderate;
    case high;

    public function pack(): string
    {
        return \pack(
            'PP',
            $this->operations(),
            $this->memory(),
        );
    }

    public function operations(): int
    {
        return match ($this) {
            self::low => \SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
            self::moderate => \SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE,
            self::high => \SODIUM_CRYPTO_PWHASH_OPSLIMIT_SENSITIVE,
        };
    }

    public function memory(): int
    {
        return match ($this) {
            self::low => \SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
            self::moderate => \SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE,
            self::high => \SODIUM_CRYPTO_PWHASH_MEMLIMIT_SENSITIVE,
        };
    }

    /**
     * @return Frame<self>
     */
    public function frame(): Frame
    {
        return Frame::chunk(16)->map(function($limits) {
            if ($this->pack() !== $limits->toString()) {
                throw new \RuntimeException('Invalid derivation key parameters');
            }

            return $this;
        });
    }
}
