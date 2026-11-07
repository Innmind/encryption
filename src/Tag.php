<?php

declare(strict_types = 1);

namespace Innmind\Encryption;

use Innmind\Immutable\Sequence;

/**
 * @psalm-immutable
 * @template T
 */
final class Tag
{
    private function __construct(
        private mixed $value,
        private bool $first,
        private bool $last,
    ) {
    }

    /**
     * @psalm-pure
     * @template A
     *
     * @param A $value
     *
     * @return self<A>
     */
    public static function of(mixed $value): self
    {
        return new self($value, true, true);
    }

    public function and(self $next): Sequence
    {
        if ($this->first && $this->last) {
            return Sequence::of(
                new self(
                    $this->value,
                    true,
                    false,
                ),
                new self(
                    $next->value,
                    false,
                    true,
                ),
            );
        }

        return Sequence::of(
            new self(
                $this->value,
                $this->first,
                false,
            ),
            new self(
                $next->value,
                false,
                true,
            ),
        );
    }

    public function first(): bool
    {
        return $this->first;
    }

    public function last(): bool
    {
        return $this->last;
    }

    public function unwrap(): mixed
    {
        return $this->value;
    }
}
