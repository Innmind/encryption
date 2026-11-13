<?php
declare(strict_types = 1);

require 'vendor/autoload.php';

use Innmind\BlackBox\{
    Application,
    Runner\Load,
    Runner\CodeCoverage,
};

Application::new($argv)
    ->map(static fn($app) => match (\getenv('BLACKBOX_ENV')) {
        'extensive' => $app->scenariiPerProof(1_000),
        'coverage' => $app
            ->scenariiPerProof(1)
            ->codeCoverage(
                CodeCoverage::of(
                    __DIR__.'/src/',
                    __DIR__.'/proofs/',
                )
                    ->dumpTo('coverage.clover'),
            ),
        default => $app,
    })
    ->tryToProve(Load::everythingIn(__DIR__.'/proofs/'))
    ->exit();
