<?php

declare(strict_types = 1);

namespace Innmind\Encryption;

use Innmind\Frame\Frame;
use Innmind\Immutable\{
    Sequence,
    Str,
};
use Innmind\Immutable\Predicate\Instance;

final class Decrypt
{
    private const int CHUNK = 8192 + \SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES;

    /** @var Frame<array{string, string}> */
    private Frame $decode;

    private function __construct(
        #[\SensitiveParameter] string $password,
    ) {
        $this->decode = Frame::chunk(4)
            ->map(static fn($magic) => match ($magic->toString()) {
                'PWE1' => $magic,
                default => throw new \RuntimeException('Invalid encrypted file'),
            })
            ->flatMap(
                static fn($magic) => Frame::chunk(\SODIUM_CRYPTO_PWHASH_SALTBYTES)->map(
                    static fn($salt) => [$magic, $salt],
                ),
            )
            ->flatMap(
                static fn($pair) => Frame::chunk(16)->map(static function($limits) use ($pair) {
                    /**
                     * @var int $ops
                     * @var int $mem
                     * @psalm-suppress PossiblyInvalidArrayAccess
                     */
                    ['ops' => $ops, 'mem' => $mem] = \unpack('Pops/Pmem', $limits->toString());

                    if (
                        $ops < \SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE ||
                        $ops > \SODIUM_CRYPTO_PWHASH_OPSLIMIT_SENSITIVE ||
                        $mem < \SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE ||
                        $mem > \SODIUM_CRYPTO_PWHASH_MEMLIMIT_SENSITIVE
                    ) {
                        throw new \RuntimeException('Invalid derivation key parameters');
                    }

                    return [
                        $pair[0]->toString().$pair[1]->toString().$limits->toString(),
                        $pair[1]->toString(),
                        $ops,
                        $mem,
                    ];
                }),
            )
            ->map(static function($tuple) use ($password) {
                [$kdfHeader, $salt, $ops, $mem] = $tuple;
                $key = \sodium_crypto_pwhash(
                    \SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES,
                    $password,
                    $salt,
                    $ops,
                    $mem,
                    \SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13,
                );

                return [
                    $kdfHeader,
                    $key,
                ];
            });
    }

    /**
     * @param Sequence<Str> $chunks
     *
     * @return Sequence<Str>
     */
    public function __invoke(Sequence $chunks): Sequence
    {
        $decode = $this->decode;

        return Sequence::lazy(static function() use ($decode, $chunks) {
            $state = '';
            $decode = $decode
                ->flatMap(
                    static function($pair) use (&$state) {
                        return Frame::chunk(\SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES)->map(
                            static function($header) use (&$pair, &$state) {
                                $state = \sodium_crypto_secretstream_xchacha20poly1305_init_pull(
                                    $header->toString(),
                                    $pair[1],
                                );
                                \sodium_memzero($pair[1]);

                                return $pair[0];
                            },
                        );
                    },
                )
                ->map(Str::of(...))
                ->map(Decrypt\Header::of(...))
                ->passthrough();

            /** @psalm-suppress MixedArgumentTypeCoercion */
            yield $chunks
                ->via($decode)
                ->flatMap(static fn($chunk) => match (true) {
                    $chunk instanceof Decrypt\Header => Sequence::of($chunk),
                    default => $chunk->chunk(self::CHUNK),
                })
                ->aggregate(static fn(Decrypt\Header|Str $a, Str $b) => match (true) {
                    $a instanceof Decrypt\Header => Sequence::of($a, $b),
                    default => $a->append($b)->chunk(self::CHUNK),
                })
                ->map(Decrypt\Chunk::of(...))
                ->aggregate(static fn(Decrypt\Chunk|Decrypt\Pull $a, Decrypt\Chunk $b) => $a->and($b))
                ->keep(Instance::of(Decrypt\Pull::class))
                ->map(static function($pull) use (&$state) {
                    [$plain, $state] = $pull($state);

                    return $plain;
                })
                ->via(Sequence\Position::tag(...))
                ->map(
                    static fn($value) => $value
                        ->unwrap()
                        ->validate($value->position()),
                );

            \sodium_memzero($state);
        })
            ->flatMap(static fn($chunks) => $chunks)
            ->map(static fn($chunk) => $chunk->toEncoding(Str\Encoding::ascii));
    }

    public static function of(#[\SensitiveParameter] string $password): self
    {
        return new self($password);
    }
}
