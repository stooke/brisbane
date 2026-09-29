#!/bin/sh

REPO=`pwd`/..
WORK_DIR=$REPO/jst

#JAVA_HOME=$WORK_DIR/jdk-25.0.4.1+1
java --enable-native-access=ALL-UNNAMED -cp .:../build/libs/jipher-jce-20.1.jar -Dsecurity.useSystemPropertiesFile=true -D -Dcom.redhat.fips=true -Djipher.openssl.useOsInstance=true FipsCheck >fips-rh.txt
./jdk-25.0.4.1+1/bin/java --enable-native-access=ALL-UNNAMED -cp .:../build/libs/jipher-jce-20.1.jar -Dsecurity.useSystemPropertiesFile=true -D -Dcom.redhat.fips=true -Djipher.openssl.useOsInstance=true  FipsCheck >fips-temurin.txt

