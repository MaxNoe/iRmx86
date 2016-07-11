from distutils.core import setup

setup(
    name='irmx86',
    version='0.1.0',
    description='ReadOnly implementation of the irmx86 file system',
    url='https://github.com/tudo-spect/iRmx86',
    author='Maximilian Nöthe',
    author_email='maximilian.noethe@tu-dortmund.de',
    license='MIT',
    py_modules=['irmx86'],
    entry_points={
        'console_scripts': ['irmx86_extract = irmx86:main'],
    }
)
