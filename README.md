## OpenSSL Authenticated Android Open Accessory (AOA) Protocal

------

More details can see blog: [http://ytliu.info/blog/2015/12/05/openssl-authenticated-android-accessory-protocol/](http://ytliu.info/blog/2015/12/05/openssl-authenticated-android-accessory-protocol/)

------

### Usage

Use 2 Android devices (Phone or Tablet)

Connect one device (act as AOA Accessory and OpenSSL Client) to the computer. (Note: this device must support USB host mode)

    $ cd aoa-acc-ssl-client
    $ ./build.sh

Connect the other device (act as AOA Device and OpenSSL Server) to the computer.

    $ cd aoa-dev-ssl-server
    $ ./build.sh

connect the two devices using USB cable and On-The-Go (OTG).

See the logs:

    $ adb logcat

------
