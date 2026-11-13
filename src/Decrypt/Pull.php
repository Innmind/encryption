<?php

declare(strict_types = 1);

namespace Innmind\Encryption\Decrypt;

use Innmind\Immutable\Sequence;
use Innmind\Immutable\Str;

final class Pull
{
    private function __construct(
        private Str $cipher,
        private Str $ad,
    ) {
    }

    /**
     * @return array{Plain, string}
     */
    public function __invoke(string $state): array
    {
        $result = \sodium_crypto_secretstream_xchacha20poly1305_pull(
            $state,
            $this->cipher->toString(),
            $this->ad->toString(),
        );

        if ($result === false) {
            throw new \RuntimeException('Wrong password or corrupted file');
        }

        [$plain, $tag] = $result;

        /** @psalm-suppress MixedArgument */
        $plain = match ($tag) {
            \SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL => Plain::last(Str::of($plain)),
            default => Plain::middle(Str::of($plain)),
        };

        return [$plain, $state];
    }

    public static function first(Str $cipher, Str $kdfHeader): self
    {
        return new self($cipher, $kdfHeader);
    }

    public static function middle(Str $cipher): self
    {
        return new self($cipher, Str::of(''));
    }

    /**
     * @return Sequence<self>
     */
    public function and(Chunk $next): Sequence
    {
        return Sequence::of($this, $next->pull());
    }
}
