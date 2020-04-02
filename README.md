# Java Card ROM Mask Generator

## Copyright and license
Copyright (C) 2020

This software is licensed under the MIT license. See [LICENSE](LICENSE.txt) file
at the root folder of the project.

## Author

  * Guillaume BOUFFARD (<mailto:guillaume.bouffard@ssi.gouv.fr>)

## Description

The Java Card ROM mask generator is a part of [CHOUPI
Project](https://github.com/choupi-project). It aims a generating a rommask
which will initialising the flash memory.


## Getting this project

To clone the repository and its dependency, you should execute the following
command:

```
git clone --recursive https://github.com/choupi-project/rommask
```

## Building

### Dependencies

The Java Card ROM Mask generator depends on:

* [CAP file manipulator](https://bitbucket.org/ssd/capmap-free): a Java library
  developed by University of Limoges SSD Team which aims at reading a Java Card
  CAP file and modifying it. This library is it a git submodule of this project.
* [Maven](https://maven.apache.org/): to build the project. To install maven,
read this [page](http://maven.apache.org/install.html) or check on you Linux
package repository.

### Building Java Card ROM mask

The main [Makefile](Makefile) is in the root directory, and compiling is as
simple as executing:

```
make
```

## Running & usage

When the ```rommask``` is build, you can run it as:

```
java -jar ./target/rommask-1.0-jar-with-dependencies.jar
```

This execution reveals required parameters:

```
Usage: java -jar target/rommask-1.0-jar-with-dependencies.jar [--compact|--toCfile]
                 <directory which contains jca files to parse> <bin> <C header> <Starting Java Card method>

  --compact: Compute only the sector where data will be there and write as a binary file.
  --compactHex ADDRESS: Compute only the sector where data will be there and write as an intel hex file.
                        The address, must be encoded in hexadecimal, set the begin address of the data to write.
  --toCFile: Generate de C file with the sector to initialize.
  out: C/C++ file where the parsed JCA files will be stored as a C-array.
  bin: Parsed JCA files will be stored in a binary file.
  C header: C header file to implement Java Card native functions.
  Starting Java Card method: The first Java Card method run when the JCVM starts.
                             This value should be as com.package.Class.method.
```

