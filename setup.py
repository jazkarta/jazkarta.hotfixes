from setuptools import setup, find_packages

version = '1.0'

setup(
    name='jazkarta.hotfixes',
    version=version,
    description="Runtime security backports for the Plone 5.2 package lines.",
    long_description=open("README.rst").read() + "\n" + open("CHANGES.rst").read(),
    classifiers=[
        "Framework :: Plone",
        "Framework :: Plone :: 5.2",
        "License :: OSI Approved :: GNU General Public License v2 (GPLv2)",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.8",
    ],
    keywords='plone security monkeypatch',
    author='Jazkarta',
    author_email='',
    url='https://github.com/jazkarta/jazkarta.hotfixes',
    license='GPLv2',
    packages=find_packages(exclude=['ez_setup']),
    namespace_packages=['jazkarta'],
    include_package_data=True,
    zip_safe=False,
    python_requires='>=3.8',
    install_requires=[
        'setuptools',
        'requests',
        'feedparser',
        'plone.app.portlets',
        'plone.app.event',
        'plone.app.content',
        'Pillow',
        'z3c.form',
        'zope.interface',
        'zope.schema',
    ],
    extras_require={
        'test': [
            'plone.app.testing',
        ],
    },
    entry_points="""
    [z3c.autoinclude.plugin]
    target = plone
    """,
)
