#!/bin/bash
PCCK=`/bin/ps -ef | grep /smartagent/Plugins/DFA/smartagent/smartagent | wc -l`

if [ "$PCCK" -gt 2 ] ; then
    PID=`ps -eaf|grep '/smartagent/Plugins/DFA/smartagent/smartagent'|grep -v grep|awk '{print $2}'`
    for i in $PID; do
        echo 'kill -9' $i
        kill -9 $i
    done
fi

PMCK=`/sbin/pidof /smartagent/Plugins/DFA/smartagent/smartagent | wc -l`

if [ "$PMCK" -eq "0" ] ; then
    su root -c "/smartagent/Plugins/DFA/smartagent/op-shell/start.sh /smartagent/Plugins/DFA/smartagent"

    if [ "$PCCK" -gt 2 ] ; then
        PID=`ps -eaf|grep '/smartagent/Plugins/DFA/smartagent/smartagent'|grep -v grep|awk '{print $2}'`
        for i in $PID; do
            echo 'kill -9' $i
            kill -9 $i
        done

        su root -c "/smartagent/Plugins/DFA/smartagent/op-shell/start.sh /smartagent/Plugins/DFA/smartagent"

    fi
fi
