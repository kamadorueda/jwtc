# Standard imports
import os
import time
import contextlib
import multiprocessing

# Third parties imports
import authlib.jose


def crack_with_random_key(args):
    """Generate a random key and use it to verify the JWT."""
    jwt, key_bytes = args
    success, tried_key = False, os.urandom(key_bytes)
    with contextlib.suppress(authlib.jose.errors.BadSignatureError):
        authlib.jose.jwt.decode(jwt, tried_key)
        success = True
    return success, tried_key


def solve(jwt: str, key_bytes: int):
    attempts: int = 0
    search_space: int = 2 ** (8 * key_bytes)
    available_cpus: int = multiprocessing.cpu_count()
    results_per_round: int = 2 ** 15

    progress: float = 0.0
    attempt_failure_probability: float = 1 - 1 / search_space

    print(f'Search space: {search_space}')

    with multiprocessing.Pool(processes=available_cpus) as workers:
        while True:
            start_time: float = time.time()
            attempts += available_cpus * results_per_round
            results = workers.imap_unordered(
                func=crack_with_random_key,
                iterable=tuple(
                    (jwt, key_bytes)
                    for _ in range(available_cpus * results_per_round)),
                chunksize=results_per_round)
            progress = 1 - attempt_failure_probability ** attempts

            success_results = tuple(filter(lambda r: r[0], results))

            if success_results:
                print('\r', end='')
                print('Solved.')
                print('  hex:', success_results[0][1].hex())
                break

            elapsed: float = time.time() - start_time
            speed: int = int(available_cpus * results_per_round / elapsed)
            remaining: int = int(search_space * (1 - progress) / speed)
            print(f'\r  '
                  f'attempts: {attempts}, '
                  f'{progress:.8f}%, '
                  f'{speed}/s, '
                  f'{remaining} remaining seconds',
                  end='')
