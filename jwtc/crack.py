# Standard imports
import os
import json
import time
import contextlib
import multiprocessing

# Third parties imports
import jose.jws
import jose.utils
import jose.exceptions


def gen_random_plain_key(key_bytes: int) -> bytes:
    """Return a suitable key for HS* signing."""
    return os.urandom(key_bytes)


def crack_with_random_key(args):
    """Generate a random key and use it to verify the JWT."""
    jwt, key_bytes, key_gen_func = args
    tried_key: bytes = key_gen_func(key_bytes)

    signing_input, crypto_segment = jwt.rsplit(b'.', 1)
    header_segment, _ = signing_input.split(b'.', 1)

    header = json.loads(
        jose.utils.base64url_decode(header_segment).decode('utf-8'))
    signature = jose.utils.base64url_decode(crypto_segment)

    crypto = jose.jwk.get_key(header['alg'])(tried_key, header['alg'])

    return crypto.verify(signing_input, signature), tried_key


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
                    (jwt, key_bytes, gen_random_plain_key)
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
