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
        ->test(static function($assert, $chunks, $password) {
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
};
