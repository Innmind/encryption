<?php

declare(strict_types = 1);

namespace Innmind\Encryption\Decrypt;

use Innmind\Immutable\Sequence;
use Innmind\Immutable\Str;

final class Chunk
{
    private function __construct(
        private Header|Str $value,
    ) {
    }

    public static function of(Header|Str $value): self
    {
        return new self($value);
    }

    /**
     * @return Sequence<Pull>
     */
    public function and(self $next): Sequence
    {
        if ($next->value instanceof Header) {
            throw new \LogicException('The header should be the first value only');
        }

        if ($this->value instanceof Header) {
            return Sequence::of(Pull::first($next->value, $this->value->unwrap()));
        }

        return Sequence::of(
            Pull::middle($this->value),
            Pull::middle($next->value),
        );
    }

    public function pull(): Pull
    {
        if ($this->value instanceof Header) {
            throw new \LogicException;
        }

        return Pull::middle($this->value);
    }
}
