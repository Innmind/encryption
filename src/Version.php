<?php

declare(strict_types = 1);

namespace Innmind\Encryption;

use Innmind\Immutable\Str;

/**
 * @psalm-immutable
 */
enum Version
{
    case v1;

    /**
     * @psalm-pure
     */
    public static function of(Str $value): self
    {
        return match ($value->toString()) {
            "IE@\x01" => self::v1,
        };
    }

    /**
     * @psalm-pure
     */
    public static function latest(): self
    {
        return self::v1;
    }

    public function sensitivity(): Sensitivity
    {
        return match ($this) {
            self::v1 => Sensitivity::moderate,
        };
    }

    /**
     * @return non-empty-string
     */
    public function toString(): string
    {
        return match ($this) {
            self::v1 => "IE@\x01",
        };
    }
}
