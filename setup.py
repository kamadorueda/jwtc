"""Setup package."""

import distutils

distutils.core.setup(
    name='jwtc',
    packages=[
        'jwtc',
    ],
    install_requires=[
        'python-jose==3.0.1',
    ],
    entry_points={
        'console_scripts': [
            'jwtc=jwtc.cli:cli',
        ],
    },
)
