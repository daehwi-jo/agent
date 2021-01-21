#!/bin/bash

PROG="smartagent/Plugins/DFA/smartagent"

LOG_FILE="/$PROG/log/update.log"

SA_PATH="/$PROG"
RUN_SA_BIN="/$PROG/smartagent"
RUN_SA_CFG="/$PROG/conf/smartagent.ini"

NEW_SA_CFG="/smartagent/Plugins/DFA/smartagent/tmp/smartagent.ini"
BAK_SA_CFG="/smartagent/Plugins/DFA/smartagent/bak/smartagent.ini"

roll_back() {
	cp $BAK_SA_CFG $RUN_SA_CFG 2>&1
}

back_up() {
	#mkdir /Smartagent/bak/ 2> /dev/null        //bak이 smartagent 코드내에서 만들어졌다는 전제 하에 주석처리함
	#cp $NEW_SA_CFG $BAK_SA_CFG
	cp $RUN_SA_CFG $BAK_SA_CFG
}

sa_start() {
	$RUN_SA_BIN -d $SA_PATH 2> /dev/null &
	sleep 1
}

clear_file() {
	rm $NEW_SA_CFG 2> /dev/null
}

##################################
# update file chk
##################################

if [ -e $NEW_SA_CFG ]
then
	echo > /dev/null
else
	echo "101" > $LOG_FILE
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
# update
##################################
LOG=`cp $NEW_SA_CFG $RUN_SA_CFG 2>&1`
ST=`echo $?`
if [ $ST != 0 ]
then
	echo "1" > $LOG_FILE
	back_up
	sa_start
	exit 1
fi

##################################
# SmartAgent start
##################################
LOG=`$RUN_SA_BIN -d $SA_PATH 2> /dev/null > /dev/null &`
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
