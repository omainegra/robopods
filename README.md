# Robopods

[![Build Status](https://travis-ci.org/omainegra/robopods.svg?branch=master)](https://travis-ci.org/omainegra/robopods)

Complementary Robovm [RoboPods](https://github.com/mobivm/robovm-robopods)

## Available pods

| Library                                          | Version | Pod version | Description                |
|--------------------------------------------------|---------|-------------|----------------------------|
| [SDWebImage](https://github.com/rs/SDWebImage)   | 4.2.3   | 0.1.0       | Asynchronous image downloader with cache support as a UIImageView category        |
| [Lottie](https://github.com/airbnb/lottie-ios)   | 2.5.0   | 0.1.0       | An iOS library to natively render After Effects vector animations        |

## Usage

### Prerequisites

* [XCode 9.2](https://developer.apple.com/xcode/)
* [JDK 8](http://www.oracle.com/technetwork/java/javase/downloads/)
* [Robovm](https://github.com/MobiVM/robovm)
* [Gradle (optional)](https://gradle.org/install/)

### Installing

#### Build frameworks

*SDWebImage*
```
$ git clone https://github.com/rs/SDWebImage.git
$ cd SDWebImage
$ git checkout tags/4.2.3
$ git submodule update --init --recursive
$
$ xcodebuild build -workspace SDWebImage.xcworkspace -scheme "SDWebImage iOS" -sdk iphoneos        // For device
$ xcodebuild build -workspace SDWebImage.xcworkspace -scheme "SDWebImage iOS" -sdk iphonesimulator // For simulator
```

*Lottie*
```
$ git clone https://github.com/airbnb/lottie-ios.git
$ cd lottie-ios
$ git checkout tags/2.5.0
$
$ xcodebuild build -project Lottie.xcodeproj -sdk iphoneos        // For device
$ xcodebuild build -project Lottie.xcodeproj -sdk iphonesimulator // For simulator
```

Copy **SDWebImage.framework** and **Lottie.framework** to `<your project>/frameworks`

#### Update `robovm.xml` configuration file
```
<frameworkPaths>
    <path>frameworks</path>
</frameworkPaths>
<frameworks>
    <framework>SDWebImage</framework>
    <framework>Lottie</framework>
    ...
</frameworks>
```

#### Add dependencies to `build.gradle`

```
// SDWebImage
compile "com.omainegra.robopods:sdwebimage:4.2.3-0.1.0"

// Lottie
compile "com.omainegra.robopods:lottie:2.5.0-0.1.0"
```

## Building manually
```
$ git clone https://github.com/omainegra/robopods.git
$ cd robopods
$ git submodule update --init --recursive
$ ./gradlew build
```

## Demo

Check the **demo** project included in this repo. It's written in [Kotlin](https://kotlinlang.org/) and feature some uses cases of the libraries

## Versioning

The version scheme is "*<library_version>*-*<pod_version>*"

## Contributing

If you want to have some other libraries included, please submit issues or pull-request.
