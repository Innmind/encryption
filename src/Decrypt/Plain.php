<?php

declare(strict_types = 1);

namespace Innmind\Encryption\Decrypt;

use Innmind\Immutable\Sequence\Position;
use Innmind\Immutable\Str;

final class Plain
{
    private function __construct(
        private Str $value,
        private bool $last,
    ) {
    }

    public static function last(Str $value): self
    {
        return new self($value, true);
    }

    public static function middle(Str $value): self
    {
        return new self($value, false);
    }

    public function validate(Position $position): Str
    {
        if (
            ($position->last() && !$this->last) ||
            ($this->last && !$position->last())
        ) {
            throw new \RuntimeException('Truncated file');
        }

        return $this->value;
    }
}
