#!/bin/bash

usage_txt="\n\n[Usage] $0 pkg-name(ex, smartagent-i3.0.0.tar)\n"

if [ -z "$1" ]
then
    echo -n "[Input] pkg-name(ex, smartagent-i3.0.0.tar) : " # -n 옵션은 뉴라인을 제거해 줍니다.
	read pkg_name
else
	echo "[Info] pkg-name :  $1"
	pkg_name=$1
fi

if [[ $pkg_name = *'--'* ]]    # 변수에 문자열을 사용할 경우 작은 따옴표(' ')를 이용하여 문자열을 둘러싸면 됨
then
	echo "패키지명에는 '-' 문자를  연속해서 사용할수 없습니다."
	echo -e "$usage_txt"  
	exit
fi

if [[ $pkg_name = *[-]* ]]
then
	echo "패키지 생성규칙(1) : 정상"
else
	echo "패키지명에는 반드시 - 문자를 포함해야 합니다."
	echo -e "$usage_txt"  
	exit
fi

if [[ $pkg_name = *'..'* ]]    # 변수에 문자열을 사용할 경우 작은 따옴표(' ')를 이용하여 문자열을 둘러싸면 됨
then
	echo "패키지명에는 '.' 문자를  연속해서 사용할수 없습니다."
	echo -e "$usage_txt"  
	exit
else
	echo "패키지 생성규칙(2) : 정상"
fi

cur_dir=`pwd`

#echo ${pkg_name%%-*}
dir_name=${pkg_name%%-*}


#echo ${pkg_name#*-}
# 현재 디렉토리에 파일찾기 
input=`find . -name $pkg_name`
for i in $input
do
	file_name=${i#*./}
#	echo $file_name 
	if [ $pkg_name = $file_name ]    # 문자를 비교: = ,  -eq 은 정수를 비교: -eq
	then
		echo "정보1: $pkg_name 은 이미존재함."
		echo -e "$usage_txt"  
		exit
	fi
done

vi ./news.txt

# 패키지명에서 버전구하기(smartagent-i1.0.0.tar --> i1.0.0)
sval=${1%.*}
ver=${sval#*-}

if [ $dir_name = "smartagent" ]
then
    chmod +x ./${dir_name}/${dir_name}

    ./pkg_shell/pversion ${dir_name} ${ver} 
    ./${dir_name}/${dir_name} -v
else
    chmod +x ./${dir_name}/${dir_name}

    ./pkg_shell/pversion ${dir_name} ${ver} 
    ./${dir_name}/${dir_name} -v

fi


sleep 2

bin_name=${pkg_name:0:5}

echo "[etc] tar cvf $pkg_name ./$dir_name --exclude \".*\""
sudo tar cvf $pkg_name $dir_name --exclude ".*" --exclude "*.-*" --exclude "dev-shell" --exclude "conf.hyung500" --exclude "*.log" 
echo -e "\n\n 일반설치용 - $pkg_name 생성완료\n"

