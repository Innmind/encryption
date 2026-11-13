<?php

declare(strict_types = 1);

namespace Innmind\Encryption;

use Innmind\Frame\Frame;
use Innmind\Immutable\{
    Sequence,
    Str,
};

final class Decrypt
{
    private const int CHUNK = 8192 + \SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES;

    /** @var Frame<array{string, Decrypt\Key}> */
    private Frame $decode;

    private function __construct(
        Password $password,
    ) {
        $this->decode = Frame::chunk(4)
            ->map(Version::of(...))
            ->flatMap(
                static fn($version) => $version
                    ->algorithm()
                    ->salt()
                    ->frame()
                    ->map(static fn($salt) => [$version, $salt]),
            )
            ->flatMap(
                static fn($pair) => $pair[0]
                    ->sensitivity()
                    ->frame()
                    ->map(static fn($limits) => [
                        $pair[0]->toString().$pair[1]->toString().$limits->pack(),
                        $pair[1]->toString(),
                        $pair[0],
                    ]),
            )
            ->map(static function($tuple) use ($password) {
                [$kdfHeader, $salt, $version] = $tuple;
                $key = new Decrypt\Key($version->algorithm()->hash()->key(
                    $password,
                    $salt,
                    $version->sensitivity(),
                ));

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
                                    $pair[1]->unwrap(),
                                );
                                $pair[1]->destroy();

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
                ->filter(static fn($chunk) => $chunk instanceof Decrypt\Header || !$chunk->empty())
                ->flatMap(static fn($chunk) => match (true) {
                    $chunk instanceof Str => $chunk->chunk(self::CHUNK),
                    default => Sequence::of($chunk),
                })
                ->aggregate(static fn(Decrypt\Header|Str $a, Str $b) => match (true) {
                    $a instanceof Str => $a->append($b)->chunk(self::CHUNK),
                    default => Sequence::of($a, $b),
                })
                ->map(Decrypt\Chunk::of(...))
                ->prepend(Sequence::of(Decrypt\Chunk::none()))
                ->aggregate(static fn(Decrypt\Chunk|Decrypt\Pull $a, Decrypt\Chunk $b) => $a->and($b))
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

    public static function of(Password $password): self
    {
        return new self($password);
    }
}
