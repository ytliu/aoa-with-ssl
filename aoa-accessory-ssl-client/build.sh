#!/bin/bash
export MY_KEYSTORE_FILE="./uas_key"
export MY_KEYSTORE_PASS="ipads123"
export MY_KEY_NAME="ipads"
export PROJ="UsbAccServer"
cd `pwd`

rm -rf obj  # obj/local/armeabi/*
rm -rf libs # libs/armeabi/

mkdir libs

android update project --target android-22 --path . --name $PROJ

echo ndk-build start
time ndk-build # 2>&1 |grep -i error

ant -q clean release

jarsigner -storepass $MY_KEYSTORE_PASS -sigalg MD5withRSA -digestalg SHA1 -keystore $MY_KEYSTORE_FILE -signedjar bin/$PROJ-release-unaligned.apk bin/$PROJ-release-unsigned.apk $MY_KEY_NAME
zipalign -f 4 bin/$PROJ-release-unaligned.apk bin/$PROJ-release.apk

#adb install -r bin/$PROJ-release.apk

