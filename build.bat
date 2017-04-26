javac -Xlint -classpath "target" -d "target" src\main\java\jfnlite\Fn.java
javac -Xlint:deprecation -classpath "target" -d "target" src\main\java\apktlog2pcap\ByteUtils.java
javac -Xlint:deprecation -classpath "target" -d "target" src\main\java\apktlog2pcap\Pcap.java
javac -Xlint:deprecation -classpath "target" -d "target" src\main\java\apktlog2pcap\LineIterator.java
javac -Xlint:deprecation -classpath "target" -d "target" src\main\java\apktlog2pcap\LogProtoParser.java
javac -Xlint:deprecation -classpath "target" -d "target" src\main\java\apktlog2pcap\ApktLog.java
javac -Xlint:deprecation -classpath "target" -d "target" src\main\java\apktlog2pcap\AppCore.java
javac -Xlint:deprecation -classpath "target" -d "target" src\main\java\apktlog2pcap\Cli.java
javac -Xlint:deprecation -classpath "target" -d "target" src\main\java\apktlog2pcap\Gui.java

jar cvfm apktlog2pcap.jar src\main\resources\Manifest.txt -C "target" .

pause