<?php

declare(strict_types = 1);

use Innmind\Encryption\{
    Encrypt,
    Decrypt,
};
use Innmind\Immutable\{
    Sequence,
    Str,
    Monoid\Concat,
};
use Innmind\BlackBox\{
    Set,
    Prove,
    Runner\Assert,
};

return static function(Prove $prove) {
    yield $prove
        ->proof('Encryption/decryption identity')
        ->given(
            Set::sequence(
                Set::strings(),
            ),
            Set::strings()->between(1, 4096),
        )
        ->test(static function(Assert $assert, $chunks, $password) {
            $encrypt = Encrypt::of($password);
            $decrypt = Decrypt::of($password);

            $assert->same(
                \implode('', $chunks),
                Sequence::of(...$chunks)
                    ->map(Str::of(...))
                    ->via($encrypt)
                    ->via($decrypt)
                    ->fold(Concat::monoid)
                    ->toString(),
            );
        });

    yield $prove
        ->proof('Encryption does not expose chunks in plain text')
        ->given(
            Set::sequence(
                Set::strings()->atLeast(4), // statistically probable that a short chunk can be found as an encrypted value
            ),
            Set::strings()->between(1, 4096),
        )
        ->test(static function(Assert $assert, $chunks, $password) {
            $encrypt = Encrypt::of($password);

            $encrypted = Sequence::of(...$chunks)
                ->map(Str::of(...))
                ->via($encrypt)
                ->fold(Concat::monoid)
                ->toString();

            $assert
                ->string($encrypted)
                ->not()
                ->empty();

            foreach ($chunks as $chunk) {
                $assert
                    ->string($encrypted)
                    ->not()
                    ->contains($chunk)
                    ->contains(\strrev($chunk));
            }
        });

    yield $prove
        ->proof('Decryption of truncated file fails')
        ->given(
            Set::strings()
                ->between(1, 4096)
                ->flatMap(
                    static fn($password) => Set::sequence(Set::strings())
                        ->map(static fn($chunks) => Sequence::of(...$chunks)->map(Str::of(...)))
                        ->map(Encrypt::of($password->unwrap()))
                        ->flatMap(
                            static fn($encrypted) => Set::integers()
                                ->between(
                                    0,
                                    $encrypted
                                        ->unwrap()
                                        ->fold(Concat::monoid)
                                        ->toEncoding(Str\Encoding::ascii)
                                        ->length() - 1,
                                )
                                ->map(static fn($truntaed) => [
                                    $encrypted->unwrap(),
                                    $password->unwrap(),
                                    $truntaed,
                                ]),
                        ),
                ),
        )
        ->test(static function(Assert $assert, $config) {
            [$encrypted, $password, $truncated] = $config;

            $assert->throws(
                static fn() => $encrypted
                    ->flatMap(static fn($chunk) => $chunk->chunk())
                    ->take($truncated)
                    ->via(Decrypt::of($password))
                    ->fold(Concat::monoid)
                    ->toString(),
            );
        });

    yield $prove
        ->proof('Decryption with wrong password fails')
        ->given(
            Set::sequence(
                Set::strings(),
            ),
            Set::strings()->between(1, 4096),
            Set::strings()->between(1, 4096),
        )
        ->exclude(static fn($_, $a, $b) => $a === $b)
        ->test(static function(Assert $assert, $chunks, $password, $wrongPassword) {
            $encrypt = Encrypt::of($password);
            $decrypt = Decrypt::of($wrongPassword);
            $encrypted = Sequence::of(...$chunks)
                ->map(Str::of(...))
                ->via($encrypt);

            $assert->throws(
                static fn() => $decrypt($encrypted)->memoize(),
            );
        });
};
