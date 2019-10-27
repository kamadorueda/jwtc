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


def gen_random_plain_key(crypto_key_bytes: int) -> bytes:
    """Return a suitable key for HS* signing."""
    return os.urandom(crypto_key_bytes)


def crack_with_random_key(args):
    """Generate a random key and use it to verify the JWT."""
    data_signed = args['data_signed']
    data_signature = args['data_signature']
    data_algorithm = args['data_algorithm']

    crypto_key_bytes = args['crypto_key_bytes']
    crypto_key_generator = args['crypto_key_generator']
    crypto_engine_class = args['crypto_engine_class']

    tried_key: bytes = crypto_key_generator(crypto_key_bytes)
    crypto_engine = crypto_engine_class(tried_key, data_algorithm)
    return crypto_engine.verify(data_signed, data_signature), tried_key


def solve(jwt: str, crypto_key_bytes: int):
    attempts: int = 0
    search_space: int = 2 ** (8 * crypto_key_bytes)
    available_cpus: int = multiprocessing.cpu_count()
    results_per_round: int = 2 ** 15

    progress: float = 0.0
    attempt_failure_probability: float = 1 - 1 / search_space

    print(f'Search space: {search_space}')

    data_signed, crypto_segment = jwt.rsplit(b'.', 1)
    header_segment, _ = data_signed.split(b'.', 1)

    header = json.loads(
        jose.utils.base64url_decode(header_segment).decode('utf-8'))
    data_signature = jose.utils.base64url_decode(crypto_segment)
    data_algorithm = header['alg']
    crypto_engine_class = jose.jwk.get_key(data_algorithm)

    with multiprocessing.Pool(processes=available_cpus) as workers:
        while True:
            start_time: float = time.time()
            attempts += available_cpus * results_per_round
            results = workers.imap_unordered(
                func=crack_with_random_key,
                iterable=tuple(
                    {
                        'data_signed': data_signed,
                        'data_signature': data_signature,
                        'data_algorithm': data_algorithm,
                        'crypto_key_bytes': crypto_key_bytes,
                        'crypto_key_generator': gen_random_plain_key,
                        'crypto_engine_class': crypto_engine_class,
                    }
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
