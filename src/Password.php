<?php

declare(strict_types = 1);

namespace Innmind\Encryption;

/**
 * @psalm-immutable
 */
final class Password
{
    /**
     * @param \SensitiveParameterValue<non-empty-string> $value
     */
    private function __construct(
        private \SensitiveParameterValue $value,
    ) {
    }

    /**
     * @psalm-pure
     *
     * @param non-empty-string $value
     */
    public static function of(#[\SensitiveParameter] string $value): self
    {
        /** @psalm-suppress TypeDoesNotContainType */
        if ($value === '') {
            throw new \DomainException('Password cannot be empty');
        }

        return new self(new \SensitiveParameterValue($value));
    }

    /**
     * @return non-empty-string
     */
    public function unwrap(): string
    {
        return $this->value->getValue();
    }
}
