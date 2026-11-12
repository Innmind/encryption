<?php

declare(strict_types = 1);

namespace Innmind\Encryption\Decrypt;

use Innmind\Immutable\Str;

/**
 * @internal
 * @psalm-immutable
 */
final class Header
{
    private function __construct(
        private Str $value,
    ) {
    }

    /**
     * @internal
     * @psalm-pure
     */
    public static function of(Str $value): self
    {
        return new self($value);
    }

    public function unwrap(): Str
    {
        return $this->value;
    }
}
