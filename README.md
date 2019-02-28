# JDSer-DComp

A Burp Extender plugin that will allow you to tamper with requests containing compressed, serialized Java objects. Useful in case you want to pen-test a Java _thick_ (or _fat_) client application.

## Features

This extender will decompress and deserialize a request, let you modify it, and then reserialize and recompress it before sending it on.

The deserialized Java objects are encoded in XML using the [XStream](http://xstream.codehaus.org/) library.

The compression format currently supported is **zlib**.

It works well with Burp's _Proxy_, _History_, _Intruder_ and _Repeater_ tools, while it only partially supports _Scanner_.

It also has the ability to use SQLMap: Copy and paste the output of the "send deserialized to intruder" into a file, and then "sqlmap.py -r --proxy "http://burp:port".

## Usage

1) Find and download client *.jar files

Few methods to locate the required jar files containing the classes we'll be deserializing:

* In case of a .jnlp file use [jnpdownloader](https://code.google.com/p/jnlpdownloader/)
* Locating jars in browser cache
* Looking for .jar in burp proxy history

Finally, create a "libs/" directory next to your burp.jar and put all the jars in it.

2) Start Burp plugin

Download from [here](https://github.com/twelvesec/JDSer-DComp/raw/master/Executables/JDSer-DComp.jar) and simply load it in the Extender tab, the Output window will list all the loaded jars from ./libs/

3) Inspect serialized Java traffic

Serialized Java content will automagically appear in the Deserialized Java input tab in appropriate locations (proxy history, interceptor, repeater, etc.) Any changes made to the XML will serialize back once you switch to a different tab or send the request.

Please note that if you mess up the XML schema or edit an object in a funny way, the re-serialization will fail and the error will be displayed in the input tab

JARs reload when the extender is loaded. Everything is written to stdout (so run java -jar burpsuite.jar) and look for error messages/problems there.

## To do

This plugin is at a somewhat primitive state, and there are many things left to be done, like:

* Supporting more compression algorithms (maybe with auto-detection)
* Better support for Burp’s Scanner
* Better exception handling
* Support for applications that utilize XML signing

## Credits

* [JDSer-ngng](https://github.com/nccgroup/JDSer-ngng)
* [khai-tran](https://github.com/khai-tran/BurpJDSer)
* [IOActives](https://github.com/IOActive/BurpJDSer-ng)
