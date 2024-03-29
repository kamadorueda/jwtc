# Standart imports
import sys
import asyncio
import argparse
import multiprocessing

# Local imports
from jwtc import crack


def notify_parameters(args):
    """Report the parameters used in the execution."""
    print(f'Attempting to crack with keys of {args.bytes * 8} bits:')
    print('  ', args.jwt)


def cli():
    """Usual entrypoint."""
    parser = argparse.ArgumentParser()
    parser.add_argument('jwt')
    parser.add_argument('-B', '--bytes', required=True, type=int)
    args = parser.parse_args()

    notify_parameters(args)

    crack.solve(
        jwt=args.jwt.encode(),
        crypto_key_bytes=args.bytes)

    sys.exit(0)
