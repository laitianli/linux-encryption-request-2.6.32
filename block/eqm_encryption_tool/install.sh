#! /bin/sh

rm -rf /etc/rc.d/init.d/eqmd
cp eqmd /etc/rc.d/init.d -f

chkconfig --del eqmd
chkconfig --add eqmd
find /etc -name "*eqmd*" 

chkconfig --level 2345 eqmd on
chkconfig --list | grep "eqmd"

rm -rf /usr/sbin/encryption_client
cp encryption_client /usr/sbin -f
chmod +x /usr/sbin/encryption_client
rm -rf /usr/sbin/eqm_fstab.conf
rm -rf /usr/sbin/eqm_network.conf
cp eqm_fstab.conf /usr/sbin -f
cp eqm_network.conf /usr/sbin -f
chmod +r /usr/sbin/*.conf
#service eqmd start
