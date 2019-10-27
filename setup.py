"""Setup package."""

import distutils

distutils.core.setup(
    name='jwtc',
    packages=[
        'jwtc',
    ],
    install_requires=[
        'authlib==0.12.1',
    ],
    entry_points={
        'console_scripts': [
            'jwtc=jwtc.cli:cli',
        ],
    },
)
