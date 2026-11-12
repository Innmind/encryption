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
                Set::strings()->atLeast(3), // statistically probable that a short chunk can be found as an encrypted value
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
};
