#!/bin/bash 

directory=$1
nic_name=$(echo $directory | awk -F '/' '{print $4}')
dir_name=$(echo $directory | awk -F '/' '{print $5}') 

echo " #### $dir_name start to run #### "

if [ $nic_name = "DFA" ]
then
    $directory/$dir_name -d $directory &
else
    $directory/$dir_name -d $directory -e $nic_name &
fi 

if [ $dir_name = "smartagent" ]
then
    rm -rf /root/cron.pm

    echo "SHELL=/bin/bash
PATH=/sbin:/bin:/usr/sbin:/usr/bin
MAILTO=root
HOME=/
	 
*/2 * * * * root  /smartagent/Plugins/DFA/smartagent/op-shell/smartagentck.sh &" >> /root/cron.pm

    CRONTAPPM="`cat /etc/crontab |grep ${directory}/op-shell/${dir_name}ck.sh | grep -v grep | wc -l`"

    if [ "$CRONTAPPM" -eq "0" ] ; then
        cat /root/cron.pm  >> /etc/crontab
    else
        echo "already writed crontab"
    fi
    rm -rf /root/cron.pm
    exit
fi
sleep 1

rm -rf /etc/logrotate.d/hydraplus


echo ""
echo ""
echo " #### $dir_name:  check now state #### "
ps -ef | grep $directory/$dir_name; sleep 1
echo ""
echo ""

