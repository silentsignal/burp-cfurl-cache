CFURL Cache inspector for Burp Suite
====================================

Building
--------

 - Install the dependencies, in case of libraries, put the JARs into `lib`
 - Execute `ant`, and you'll have the plugin ready in `burp-cfurl-cache.jar`

Dependencies
------------

 - JDK 1.7+ (tested on OpenJDK 8, Debian/Ubuntu package: `openjdk-8-jdk`)
 - Apache ANT (Debian/Ubuntu package: `ant`)
 - SQLite JDBC Driver from https://github.com/xerial/sqlite-jdbc

License
-------

The whole project is available under MIT license, see `LICENSE.txt`,
except for the classes

 - `Base64`
 - `XMLParseException`
 - `XMLElement`
 - `BinaryPListParser`

which were taken from the Quaqua project by Werner Randelshofer, and
are licensed under the Modified BSD License, see `quaqua-license.html`.
