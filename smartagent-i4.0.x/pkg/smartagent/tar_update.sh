#!/bin/bash

PROG="smartagent/Plugins/DFA/smartagent"
LOG_FILE="/$PROG/log/update.log"

TAR_PATH="/smartagent/Plugins/DFA"
SA_PATH="/$PROG"

RUN_SA_BIN="/$PROG/smartagent"
RUN_SA_CFG="/$PROG/conf/smartagent.ini"

ORG_SA_PLG="/smartagent/Plugins/DFA/smartagent/conf/smartagent.db"
BAK_SA_PLG="/smartagent/Plugins/DFA/smartagent/bak/conf/smartagent.update"
OLD_SA_PLG="/smartagent/Plugins/DFA/smartagent/bak/conf/smartagent.backup"

NEW_SA_TAR="/smartagent/Plugins/DFA/smartagent/tmp/$1"
NEW_SA_CFG="/smartagent/Plugins/DFA/smartagent/tmp/smartagent.ini"

BAK_SA_TAR="/smartagent/Plugins/DFA/smartagent/bak/smartagent.tar"
BAK_SA_CFG="/smartagent/Plugins/DFA/smartagent/bak/smartagent.ini"

roll_back() {
	tar -xvf $BAK_SA_TAR -C $TAR_PATH 2>&1
	cp $BAK_SA_CFG $RUN_SA_CFG 2>&1
        cp $OLD_SA_PLG $ORG_SA_PLG
	echo "roll_back" >> $LOG_FILE
}

back_up() {
	#mkdir /$PROG/bak/$PROG 2> /dev/null
	cp $NEW_SA_TAR $BAK_SA_TAR
	cp $NEW_SA_CFG $BAK_SA_CFG
}

sa_start() {
	#$RUN_SA_BIN -d $SA_PATH 2> /dev/null &
        /smartagent/Plugins/DFA/smartagent/op-shell/start.sh /smartagent/Plugins/DFA/smartagent
	sleep 1
}

clear_file() {
	rm $NEW_SA_TAR 2> /dev/null
	rm $NEW_SA_CFG 2> /dev/null
}

##################################
# update file chk
##################################
if [ -e $NEW_SA_TAR ]
then
	echo > /dev/null
else
	echo "100" > $LOG_FILE
	clear_file
	sa_start
	exit 1
fi

##################################
# SmartAgent run chk
##################################
cnt=0;
while [ $cnt -lt 3 ]
do
	PID=`/sbin/pidof "smartagent"`
	if [ "$PID" == "" ]
	then
		break;
	fi

	cnt=$((${cnt}+1))
	sleep 1;
done

if [ $cnt -eq 3 ]
then
	PID=`/sbin/pidof "smartagent"`
	if [ "$PID" != "" ]
	then
		killall "smartagent"
		sleep 1
	fi
fi

##################################
# backup Plugins list
##################################
cp $ORG_SA_PLG $BAK_SA_PLG
cp $RUN_SA_CFG $BAK_SA_CFG

##################################
# update
##################################
LOG=`tar -xvf $NEW_SA_TAR -C $TAR_PATH 2>&1`
ST=`echo $?`
if [ $ST != 0 ]
then
	echo "104" > $LOG_FILE
	roll_back
	clear_file
	sa_start
	exit 1
fi

LOG=`cp $NEW_SA_CFG $RUN_SA_CFG 2>&1`
ST=`echo $?`
if [ $ST != 0 ]
then
        echo "110" > $LOG_FILE
        roll_back
        clear_file
        sa_start
        exit 1
fi

##################################
# backup Plugins list
##################################
cp $BAK_SA_PLG $ORG_SA_PLG

##################################
# SmartAgent start
##################################
#LOG=`$RUN_SA_BIN -d $SA_PATH 2> /dev/null > /dev/null &`
LOG=`$SA_PATH/op-shell/start.sh $SA_PATH 2> /dev/null > /dev/null &`
ST=`echo $?`
if [ $ST != 0 ]
then
	echo "106" > $LOG_FILE
	roll_back
	clear_file
	sa_start
	exit 1
fi

##################################
# run chk
##################################
sleep 1

PID=`/sbin/pidof "smartagent"`
if [ "$PID" = "" ]
then
	echo "107" > $LOG_FILE
	roll_back
	clear_file
	sa_start
	exit 1
fi

echo "1" > $LOG_FILE

back_up
clear_file
exit 0
