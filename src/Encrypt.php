<?php

declare(strict_types = 1);

namespace Innmind\Encryption;

use Innmind\Immutable\{
    Sequence,
    Str,
};

final class Encrypt
{
    private function __construct(
        private Password $password,
    ) {
    }

    /**
     * @param Sequence<Str> $chunks
     *
     * @return Sequence<Str>
     */
    public function __invoke(Sequence $chunks): Sequence
    {
        $password = $this->password;

        return Sequence::lazy(static function() use ($chunks, $password) {
            $salt = \random_bytes(\SODIUM_CRYPTO_PWHASH_SALTBYTES);
            $key = \sodium_crypto_pwhash(
                \SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES,
                $password->unwrap(),
                $salt,
                \SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE,
                \SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE,
                \SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13,
            );
            $kdfHeader = \sprintf(
                'PWE1%s%s',
                $salt,
                \pack(
                    'PP',
                    \SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE,
                    \SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE,
                ),
            );

            /**
             * @var string $header
             */
            [$state, $header] = \sodium_crypto_secretstream_xchacha20poly1305_init_push($key);
            \sodium_memzero($key);

            yield Sequence::of($kdfHeader, $header);

            yield $chunks
                ->filter(static fn($chunk) => !$chunk->empty())
                ->add(Str::of('')) // to make sure there is always at least one chunk
                ->map(static fn($chunk) => $chunk->toEncoding(Str\Encoding::ascii))
                ->aggregate(
                    static fn(Str $a, Str $b) => match ($b->empty()) {
                        true => $a->chunk(8192), // this removes the appended empty chunk if there's at least one other chunk
                        false => $a
                            ->append($b)
                            ->chunk(8192),
                    },
                )
                ->map(static fn($chunk) => $chunk->toString())
                ->via(Sequence\Position::tag(...))
                ->map(
                    static function($value) use (&$state, $kdfHeader) {
                        return \sodium_crypto_secretstream_xchacha20poly1305_push(
                            $state,
                            $value->unwrap(),
                            match ($value->first()) {
                                true => $kdfHeader,
                                false => '',
                            },
                            match ($value->last()) {
                                true => \SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL,
                                false => \SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE,
                            },
                        );
                    },
                );

            /** @psalm-suppress MixedArgument */
            \sodium_memzero($state);
        })
            ->flatMap(static fn($chunks) => $chunks)
            ->map(Str::of(...))
            ->map(static fn($chunk) => $chunk->toEncoding(Str\Encoding::ascii));
    }

    public static function of(Password $password): self
    {
        return new self($password);
    }
}
