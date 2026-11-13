<?php

declare(strict_types = 1);

namespace Innmind\Encryption\Decrypt;

final class Key
{
    public function __construct(
        private string $value,
    ) {
    }

    public function unwrap(): string
    {
        return $this->value;
    }

    public function destroy(): void
    {
        /** @psalm-suppress PossiblyNullPropertyAssignmentValue If the PHP Doc is to be belived this should not happen */
        \sodium_memzero($this->value);
    }
}
