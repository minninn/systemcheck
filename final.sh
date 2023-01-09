#!/bin/bash

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
    FILES=`find / ! \( -path '/proc' -prune \) -type f -perm -2 2>/dev/null`
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
    FILES=`find /dev -type f 2>/dev/null`
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
