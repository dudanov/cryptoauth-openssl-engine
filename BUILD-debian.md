Как собрать пакеты для Debian (Jessie-compatible) кросс-компиляцией
===================================================================

```
$ wbdev root
# echo 'deb http://mirror.yandex.ru/debian jessie-backports main' > /etc/apt/sources.list.d/jessie-backports.list
# dpkg --add-architecture armel
# dpkg --add-architecture armhf
# apt-get update && apt-get -t jessie-backports install libssl-dev:armel libssl-dev:armhf
# debuild -uc -us -b -aarmel
# debuild -uc -us -b -aarmhf
```
