#!/bin/bash

#20230228 +windows

rm -f active.sh
touch active.sh
chmod +x active.sh

check_vulnerable() {
    echo ''
    #U-01
    echo 'U-01: /etc/ssh/sshd_config'
    CHK=`cat /etc/ssh/sshd_config | grep -i permitrootlogin | cut -d " " -f2`
    MSG='...Vulnerable'
    for string in $CHK
    do
        if [ $string == "No" ] || [ $string == "no" ];then
            MSG='...OK'
        fi
    done
    echo $MSG

    if [ $MSG == '...Vulnerable' ];then
        echo "sed -i 's/#PermitRootLogin .*$/PermitRootLogin No/' /etc/ssh/sshd_config" >> active.sh
        echo "sed -i 's/PermitRootLogin .*$/PermitRootLogin No/' /etc/ssh/sshd_config" >> active.sh
    fi

    echo 'U-01: /etc/pam.d/login'
    CHK=`cat /etc/pam.d/login | grep -i "pam_securetty.so"`
    
    if [ "$CHK" == '' ];then
        MSG='...Vulnerable'
    else
        MSG='...OK'
    fi

    echo $MSG

    if [ $MSG == '...Vulnerable' ];then
        echo 'echo "auth	required	`find / -name pam_securetty.so -type f 2>/dev/null`" >> /etc/pam.d/login' >> active.sh
    fi


    echo ''
    #U-02
    echo 'U-02: /etc/security/pwquality.conf'

    if [ `cat /etc/security/pwquality.conf | grep -i "lcredit.*$" | cut -d "=" -f2` -le -1 ];then
        echo 'lcredit ...OK'
    else
        echo 'lcredit ...Vulnerable'
        echo "sed -i 's/# lcredit.*$/lcredit = -1/' /etc/security/pwquality.conf" >> active.sh
        echo "sed -i 's/lcredit.*$/lcredit = -1/' /etc/security/pwquality.conf" >> active.sh
    fi

    if [ `cat /etc/security/pwquality.conf | grep -i "ucredit.*$" | cut -d "=" -f2` -le -1 ];then
        echo 'ucredit ...OK'
    else
        echo 'ucredit ...Vulnerable'
        echo "sed -i 's/# ucredit.*$/ucredit = -1/' /etc/security/pwquality.conf" >> active.sh
        echo "sed -i 's/ucredit.*$/ucredit = -1/' /etc/security/pwquality.conf" >> active.sh
    fi

    if [ `cat /etc/security/pwquality.conf | grep -i "dcredit.*$" | cut -d "=" -f2` -le -1 ];then
        echo 'dcredit ...OK'
    else
        echo 'dcredit ...Vulnerable'
        echo "sed -i 's/# dcredit.*$/dcredit = -1/' /etc/security/pwquality.conf" >> active.sh
        echo "sed -i 's/dcredit.*$/dcredit = -1/' /etc/security/pwquality.conf" >> active.sh
    fi

    if [ `cat /etc/security/pwquality.conf | grep -i "ocredit.*$" | cut -d "=" -f2` -le -1 ];then
        echo 'ocredit ...OK'
    else
        echo 'ocredit ...Vulnerable'
        echo "sed -i 's/# ocredit.*$/ocredit = -1/' /etc/security/pwquality.conf" >> active.sh
        echo "sed -i 's/ocredit.*$/ocredit = -1/' /etc/security/pwquality.conf" >> active.sh
    fi

    if [ `cat /etc/security/pwquality.conf | grep -i "minlen.*$" | cut -d "=" -f2` -ge 8 ];then
        echo 'minlen ...OK'
    else
        echo 'minlen ...Vulnerable'
        echo "sed -i 's/# minlen.*$/minlen = 8/' /etc/security/pwquality.conf" >> active.sh
        echo "sed -i 's/minlen.*$/minlen = 8/' /etc/security/pwquality.conf" >> active.sh
    fi

    if [ `cat /etc/security/pwquality.conf | grep -i "difok.*$" | cut -d "=" -f2` -ge 10 ];then
        echo 'difok ...OK'
    else
        echo 'difok ...Vulnerable'
        echo "sed -i 's/# difok.*$/difok = 10/' /etc/security/pwquality.conf" >> active.sh
        echo "sed -i 's/difok.*$/difok = 10/' /etc/security/pwquality.conf" >> active.sh
    fi


    echo ''
    #U-04
    echo 'U-04: Shadow /etc/passwd'

    if [ `cat /etc/passwd | grep ^root | cut -d ":" -f2` == "x" ];then
        echo "...OK"
    else
        echo "...Vulnerable"
        echo "pwconv" >> active.sh
    fi

    
    echo ''
    #U-06
    echo 'U-06: nouser/nogroup'
    if [ -z "`find / -nouser -o -nogroup 2>/dev/null`" ];then
        echo '...OK'
    else
        echo '...Vulnerable'
        echo 'FILES=`find / -nouser -o -nogroup 2>/dev/null`' >> active.sh
        echo 'for FILE in $FILES' >> active.sh
        echo 'do' >> active.sh
        echo '    sudo rm -rf $FILE' >> active.sh
        echo 'done' >> active.sh
    fi


    echo ''
    #U-07
    echo 'U-07: Permission /etc/passwd'
    PERM=`find /etc/passwd ! -perm /133 -user root 2>/dev/null` #perm -le 644 
    if [ -n "$PERM" ];then
        echo "...OK"
    else
        echo "...Vulnerable"
        echo 'chown root /etc/passwd' >> active.sh
        echo 'chmod 644 /etc/passwd' >> active.sh
    fi


    echo ''
    #U-08
    echo 'U-08: Permission /etc/shadow'
    PERM=`find /etc/shadow ! -perm /377 -user root 2>/dev/null` #perm -le 400
    if [ -n "$PERM" ];then
        echo "...OK"
    else
        echo "...Vulnerable"
        echo 'chown root /etc/shadow' >> active.sh
        echo 'chmod 400 /etc/shadow' >> active.sh
    fi
        
    
    echo ''
    #U-09
    echo 'U-09: Permission /etc/hosts'
    PERM=`find /etc/hosts ! -perm /177 -user root 2>/dev/null` #perm -le 600
    if [ -n "$PERM" ];then
        echo "...OK"
    else
        echo "...Vulnerable"
        echo 'chown root /etc/hosts' >> active.sh
        echo 'chmod 600 /etc/hosts' >> active.sh
    fi


    echo ''
    #U-12
    echo 'U-12: Permission /etc/services'
    PERM=`find /etc/services ! -perm /133 \( -user root -o -user bin \) 2>/dev/null` #perm -le 644
    if [ -n "$PERM" ];then
        echo "...OK"
    else
        echo "...Vulnerable"
        echo 'chown root /etc/services' >> active.sh
        echo 'chmod 644 /etc/services' >> active.sh
    fi


    echo ''
    #U-13
    echo 'U-13: Find SUID/SGID'
    for FILE in `find / -user root -type f \( -perm -04000 -o -perm -02000 \) 2>/dev/null`
    do
        echo $FILE
    done


    echo ''
    #U-14
    echo 'U-14: Permission Startup/ENV'
    FILES=`find ~ -type f -name ".*" -perm /002 -user root 2>/dev/null`
    if [ "$FILES" != '' ];then 
        echo "...Vulnerable"
        for FILE in $FILES
        do
            echo $FILE
            echo "chmod o-w $FILE" >> active.sh
        done
    else
        echo "...OK"
    fi


    echo ''
    #U-15
    echo 'U-15: World Writable File'
    FILES=`find / ! \( -path '/proc' -prune \) ! \( -path '/sys/fs/cgroup/memory' -prune \) -type f -perm -2 2>/dev/null`
    if [ "$FILES" != '' ];then
        echo "...Vulnerable"
        for FILE in $FILES
        do
            echo $FILE
            echo "chmod o-w $FILE" >> active.sh
        done
    else
        echo "...OK"
    fi


    echo ''
    #U-16
    echo 'U-16: Not Exist Device File in /dev'
    FILES=`find /dev ! \( -path '/dev/console' -prune \) -type f 2>/dev/null`
    if [ "$FILES" != '' ];then
        echo "...Vulnerable"
        for FILE in $FILES
        do
            echo $FILE
            echo "rm -f $FILE" >> active.sh
        done
    else
        echo "...OK"
    fi
        

    echo ''
    #U-20
    echo 'U-20: Disable Anonymous FTP'
    ANONY_FTP=`cat /etc/vsftpd/vsftpd.conf | grep anonymous_enable | cut -d "=" -f2`
    if [ "${ANONY_FTP^^}" != "NO" ];then
        echo "...Vulnerable"
        MSG=`cat /etc/vsftpd/vsftpd.conf | grep anonymous_enable`
        echo "sed -i 's/$MSG/anonymous_enable=NO/' /etc/vsftpd/vsftpd.conf" >> active.sh
    else
        echo "...OK"
    fi       


    echo ''
    #U-23
    echo 'U-23: Disable echo, daytime, discard, chargen Services'
    FILENAME=("echo" "discard" "daytime" "chargen")
    DGST=("dgram" "stream")
    MSG="...OK"
    
    for filename in ${FILENAME[@]}
    do
        for dgst in ${DGST[@]}
        do
            GET_OPT=`cat /etc/xinetd.d/$filename-$dgst | grep disable | cut -d "=" -f2`
            GET_OPT=${GET_OPT/ /}
            GET_OPT=${GET_OPT,,}
            if [ "$GET_OPT" != "yes" ]; then
                MSG="...Vulnerable"
                # 추후 작업 필요
            fi
        done
    done
    
    echo $MSG


    echo ''
    #U-24
    echo 'U-24: NFS DIR List'
    NFS_DIR=`exportfs -v | cut -f1`
    echo $NFS_DIR
    echo "${NFS_DIR/ /\n}"


    echo ''
    #U-55
    echo 'U-55: Disable|Permission /etc/hosts.lpd'
    FILE=`find /etc/hosts.lpd \( ! -user root -o -perm /177 \) 2>/dev/null`
    if [ -n "$FILE" ];then
        echo "...Vulnerable"
        echo 'chmod 600 /etc/hosts.lpd; chown root /etc/hosts.lpd' >> active.sh
    else
        echo "...OK"
    fi


    echo ''
    #U-56
    echo 'U-56: set umask'
    FILES=`cat /etc/bashrc | grep -P "umask [0-9]+" | grep -o "[0-9]*"`
    MSG='...OK'
    for FILE in $FILES
    do
        if [ $FILE -lt 022 ] || [[ "$FILE" =~ '5' ]];then
            echo "sed -i 's/umask $FILE/umask 022/' /etc/bashrc" >> active.sh
            MSG='...Vulnerable'
        fi
    done

    echo $MSG


    echo ''
    #U-57
    echo 'U-57: Permission Home DIR'
    MSG='...OK'
    for NAME in `cat /etc/passwd | cut -d " " -f1`
    do
        if [ `echo $NAME | cut -d ":" -f3` -ge 1000 ] && [ "`echo $NAME | cut -d ':' -f1`" != 'nobody' ]; then
            USER_NAME=`echo $NAME | cut -d ":" -f1`
            if [ -n "`find /home/$USER_NAME \( ! -user $USER_NAME -o -perm /002 \) -type d`" ]; then
                MSG='...Vulnerable'
                echo "chown $USER_NAME:$USER_NAME /home/$USER_NAME" >> active.sh
                echo "chmod o-w /home/$USER_NAME" >> active.sh
            fi
        fi
    done

    echo $MSG


    echo ''
    #U-58
    echo 'U-58: Exists Home DIR'
    MSG='...OK'
    ARR_NAME=( `cat /etc/passwd | cut -d ":" -f1` )
    ARR_GID=( `cat /etc/passwd | cut -d ":" -f4` )
    ARR_UID=( `cat /etc/passwd | cut -d ":" -f3` )
    ARR_DIR=( `cat /etc/passwd | cut -d ":" -f6` )
    for (( num=0; num<${#ARR_UID[@]}; num++ ))
    do
        if [ ${ARR_UID[$num]} -ge 1000 ] && [ ${ARR_UID[$num]} -lt 65535 ] && [ "${ARR_NAME[$num]}" != 'nobody' ]; then  #find user account
            if [ "${ARR_DIR[$num]}" != "/home/${ARR_NAME[$num]}" ]; then  #match /home/'user account'
                MSG='...Vulnerable'
                CHANGE=`cat /etc/passwd | grep ^${ARR_NAME[$num]}:`
                echo "sed -i 's/${CHANGE//\//\\/}/${ARR_NAME[$num]}:x:${ARR_UID[$num]}:${ARR_GID[$num]}::\/home\/${ARR_NAME[$num]}:\/bin\/bash/' /etc/passwd" >> active.sh 
            fi
        fi
    done
    
    echo $MSG

}


#Function
check_vulnerable


if [ -s active.sh ];then
    echo ''
    echo 'RUN active.sh OR configure active.sh'
    echo ''
    echo 'RUN active.sh? (y/n)'
    read MSG
    if [ $MSG == 'y' ] || [ $MSG == 'Y' ];then
        ./active.sh
        rm -f active.sh
        check_vulnerable
    fi
else
    echo ''
    echo 'Process Done'
fi
