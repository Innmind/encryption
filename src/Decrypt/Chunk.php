<?php

declare(strict_types = 1);

namespace Innmind\Encryption\Decrypt;

use Innmind\Immutable\Sequence;
use Innmind\Immutable\Str;

final class Chunk
{
    private function __construct(
        private Header|Str|null $value,
    ) {
    }

    /**
     * @return array{Plain, string}
     */
    public function __invoke(string $state): array
    {
        // the argument and return type is only here for psalm for the
        // compatibility with Pull::__invoke()
        throw new \RuntimeException('Truncated file');
    }

    public static function of(Header|Str $value): self
    {
        return new self($value);
    }

    public static function none(): self
    {
        return new self(null);
    }

    /**
     * @return Sequence<Pull|self>
     */
    public function and(self $next): Sequence
    {
        if (\is_null($this->value)) {
            return Sequence::of($next);
        }

        if (\is_null($next->value)) {
            throw new \LogicException('Multiple "none" chunk inserted in the sequence');
        }

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
        if (!($this->value instanceof Str)) {
            throw new \LogicException;
        }

        return Pull::middle($this->value);
    }
}
