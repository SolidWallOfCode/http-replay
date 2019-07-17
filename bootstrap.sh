#!/bin/bash
# This script is targeted at having the base setup to run the build.
# it will let the build system check for stuff needed to have the build work.
# the only "exception" is to deal with yinst stuff as this is "complex" to get correct
# for the packaging logic to work

set -o pipefail
# some util functions
while getopts 'vh' opt
do
       case $opt in
       v) Verbose=1;;
       h) ShowUsage=1;;
       esac
done
shift $((OPTIND - 1))

if [[ $ShowUsage == 1 ]]; then
    echo "Run as '. bootstrap.sh' to setup environment for build"
    echo "-v show output of commands"
    echo "-h show help"
    unset ShowUsage
    return &> /dev/null || exit
fi

function Fatal
{
    echo "$@"
    return &> /dev/null || exit
}

function Run
{
    if [[ $Verbose == 1 ]]; then
       echo "$@"
       "$@" || Fatal "Failed to run: $@"
    else
       "$@" &> /dev/null
    fi
}

output=/dev/stdout
#output=/dev/null

function Log () 
{
    echo ""
    echo "***************************"
    echo "$@"
    echo "---------------------------"
}

#check if this RHEL or CentOS
isRH=$(awk '{if (/Red Hat/) {print 1} else {print 0}}' /etc/redhat-release 2> /dev/null)
isCentos=$(awk '{if (/CentOS/) {print 1} else {print 0}}' /etc/redhat-release 2> /dev/null)

if [[ $isCentos == 1 || $isRH == 1 ]]; then
    # should have some logic for fedora
    Log "This is a Red Hat based system"
    isRHBased="1"    
fi
[[ $(grep -c 'release 7' /etc/redhat-release) == 1 ]] && is7=1
[[ $(grep -c 'release 6' /etc/redhat-release) == 1 ]] && is6=1

############################################
## check that the expected repos exist

# check the edge_rpm is added to system
if [[ $isRHBased == 1 && ! -f /etc/yum.repos.d/edge_rpms.repo ]]; then
    # for the edge RPMs .. note we have to edit the repo file for centos.. need to see what we can do to prevent this
    # until then this will "fail" for Centos systems if adding yahoo-openssl
    Log "Adding edge_rpms repo"
    Run sudo yum-config-manager --add-repo=https://edge.artifactory.ouroath.com:4443/artifactory/edge_rpms/edge_rpms.repo 
fi
# check that oath-rpms is on the system
if [[ $isRHBased == 1 && ! -f /etc/yum.repos.d/oath-rpms-latest.repo && $is7 == 1 ]]; then
    Log "Adding DPS oath-rpm-latest repo"
    Run sudo yum-config-manager --add-repo=https://artifactory.ouroath.com/artifactory/list/oath-rdrs/7Server/release/x86_64
    Run sudo yum install -y oath-rpms-latest --nogpgcheck 
fi

if [[ $isRH == 1 && ! -f /etc/yum.repos.d/y-rhscl.repo ]]; then
    # for dev toolset and epel
    Log "Adding scl and epel repos"
    if [[ $is6 == 1 ]]; then
        Run sudo yum install --enablerepo=y-extras -y y-rhscl-repo y-epel-release 
    else
        Run sudo yum install -y y-rhscl-repo y-epel-release 
    fi
fi
if [[ $isCentos == 1 && ! -f /etc/yum.repos.d/CentOS-SCLo-scl-rh.repo ]]; then
    Log "Adding scl and epel repos"
    sudo yum install -y centos-release-scl-rh epel-release &> /dev/null
fi
if [[ $isRH == 1 && $is7 == 1 ]]; then
    Log "Check that certain repos are enabled"
    hasEdgeStable=$(sudo yum repoinfo edge_rpms-stable | grep "Repo-status  : enabled";echo $?)
    hasEdgeLatest=$(sudo yum repoinfo edge_rpms-latest | grep "Repo-status  : enabled";echo $?)
    hasEPEL=$(sudo yum repoinfo epel | grep "Repo-status  : enabled";echo $?)
fi
if [[ $isRH == 1 && $hasEdgeLatest == 1 ]]; then
    Log "Enable edge_rpms-latest"
    Run sudo yum-config-manager --enable edge_rpms-latest
elif [[ $isRH == 1 && $is6 == 1 ]]; then
    Log "Enable edge_rpms-latest"
    Run sudo yum-config-manager --enable edge_rpms-latest
fi
if [[ $isRH == 1 && $hasEdgeStable == 1 ]]; then
    Log "Enable edge_rpms-stable"
    Run sudo yum-config-manager --enable edge_rpms-stable 
#elif [[ $isRH == 1 && $is6 == 1 ]]; then
    #Log "Enable edge_rpms-stable"
    #Run sudo yum-config-manager --enable edge_rpms-stable 
fi
if [[ $isRH == 1 && $hasEPEL == 1 ]]; then
    Log "Enable epel"
    Run sudo yum-config-manager --enable epel 
elif [[ $isRH == 1 && $is6 == 1 ]]; then
    Log "Enable epel"
    Run sudo yum-config-manager --enable epel 
fi

# yinst 6 should always have yinst on the system .. only ylinux 7 or centos 7 cases should not
# centos 6 case is not supported for yinst (I don't have a hack to work around it at this time)
if [[ $isRHBased == 1 && ! -f /usr/local/bin/yinst && $is7 == 1 ]] ; then
    Log "Adding yinst"
    Run sudo yum install -y perl-WWW-Mechanize\
    perl-JSON\
    perl-Crypt-SSLeay\
    perl-YAML-Syck\
    perl-IPC-Run\
    perl-Log-Log4perl\
    perl-XML-SAX-Expat\
    perl-XML-SAX\
    perl-IO-stringy\
    perl-File-FnMatch\
    perl-Exception-Class\
    perl-File-Slurp\
    perl-XML-Simple\
    perl-Parse-RecDescent\
    perl-Pod-Parser\
    perl-YAML\
    perl-TermReadKey\
    yinst\
    sudo\
    wget\
    openssl-devel
    export PATH=/home/y/bin64:/home/y/bin${PATH:+:${PATH}}
fi

rpms="perl-ExtUtils-MakeMaker \
c-ares-devel \
luajit-devel \
docbook-style-xsl \
file-devel \
libyaml-devel \
gmp-devel \
json-c-devel \
protobuf-c-devel \
boost-devel \
libevent-devel \
libidn-devel \
libxslt-devel \
rpm-build \
libzip-devel \
readline-devel \
cppunit-devel \
hwloc-devel \
libcap-devel \
libffi-devel \
pcre-devel \
tcl-devel \
git \
zlib-devel \
asciidoc \
xmlto \
openssl-devel \
expat-devel \
perl-devel \
gettext-devel \
wget \
httpd24-curl \
httpd24-libcurl-devel \
rh-python36-python-jinja2 \
rh-python36-python-virtualenv \
httpd-tools \
devtoolset-8-gcc-c++ \
devtoolset-8-libasan-devel \
libasan3  \
devtoolset-6-gcc-c++  \
devtoolset-6-libasan-devel \
autoconf \
automake \
make \
libtool
"

if [[ $isRHBased && $is7 == 1 ]]; then
    rpms="$rpms hiredis-devel \
    hiredis-devel 
    "
fi
if [[ $isRHBased == 1 &&  $(rpm -q $rpms >/dev/null 2>&1;echo $?) -ne 0 ]] ; then
    Log "Add base package for rhel or centos needed for build"
    Run sudo yum install -y $rpms
fi

if [[ $isRHBased == 1 &&  ! -f /home/y/bin/yinst_create && $is7 == 1 ]] ; then
    Log "Add packages to build yicfs"
    Run sudo yum -y install perl-autodie 
    Run yinst install dist_tools -yes -br test 
fi
if [[ $isRHBased == 1 &&  ! -f /home/y/bin/yinst_create && $is6 == 1 ]] ; then
    Log "Add packages to build yicfs"
    Run yinst install dist_tools -yes 
fi
if [ -f /opt/rh/devtoolset-8/enable ]; then
    Log "Enable gcc/g++ 8"
    . /opt/rh/devtoolset-8/enable     
fi
if [[ $isRHBased == 1 && ! -f /usr/local/git/bin/git ]]; then
    Log "git 2.19 is not on the box.. downloading and building"
    Run . /opt/rh/httpd24/enable
    Run wget https://github.com/git/git/archive/v2.19.2.tar.gz 
    Run tar -zxvf v2.19.2.tar.gz 
    Run cd git-2.19.2 
    Run make clean 
    Run make configure 
    Run ./configure CFLAGS='-I/opt/rh/httpd24/root/usr/include/' LDFLAGS='-L/opt/rh/httpd24/root/usr/lib64/' --prefix=/usr/local/git 
    Run sudo make install -j4 
    
    Log "cleaning up build files"    
    Run cd .. 
    Run sudo rm -rf git-2.19.2 v2.19.2.tar.gz 
    
    Log "Enable git 2.19 on the path"    
    export PATH=/usr/local/git/bin:$PATH

    Log "Configure git to support tls 1.2"
    Run sudo /usr/local/git/bin/git config --global http.sslVersion tlsv1.2 

elif [[ -f /usr/local/git/bin/git ]]; then
    Log "Enable git 2.19 on the path"
    Run . /opt/rh/httpd24/enable 
    export PATH=/usr/local/git/bin:$PATH
fi
if [[ $isRH == 1 && $is6 == 1 ]]; then
    Log "Install better autoconf"
    Run curl -L -O http://ftp.gnu.org/gnu/autoconf/autoconf-2.68.tar.gz
    Run tar zxf autoconf-2.68.tar.gz
    Run cd autoconf-2.68
    Run ./configure
    Run make
    Run sudo make install
    Run cd ..
    Run sudo rm -rf autoconf-2.68 autoconf-2.68.tar.gz
    Log "Install better automake"
    Run curl -L -O http://ftp.gnu.org/gnu/automake/automake-1.16.1.tar.gz
    Run tar zxf automake-1.16.1.tar.gz
    Run cd automake-1.16.1
    Run ./configure
    Run make
    Run sudo make install
    Run cd ..
    Run sudo rm -rf automake-1.16.1 automake-1.16.1.tar.gz
    Log "Install better libtool"
    Run curl -L -O http://ftp.gnu.org/gnu/libtool/libtool-2.4.6.tar.gz
    Run tar zxf libtool-2.4.6.tar.gz
    Run cd libtool-2.4.6
    Run ./configure
    Run make
    Run sudo make install
    Run cd ..
    Run sudo rm -rf libtool-2.4.6 libtool-2.4.6.tar.gz
fi
if [ -f /opt/rh/devtoolset-8/enable ]; then
    Log "Enable gcc/g++ 8"
    . /opt/rh/devtoolset-8/enable     
fi
if [[ $(which patchelf >/dev/null 2>&1;echo $?) -ne 0 ]] ; then
    Log "Adding patchelf"
    Run git clone https://github.com/NixOS/patchelf.git 
    Run cd patchelf 
    Run ./bootstrap.sh 
    Run ./configure 
    Run make  
    Run sudo make install 
    Run cd ..
    Run rm -rf patchelf 
fi
if [[ -f /opt/rh/rh-python36/enable ]]; then
    Log "enable python 3.6"
    Run . /opt/rh/rh-python36/enable 
fi
if [[ ! -d build-env ]]; then
    Log "Setting up python virtualenv"
    Run virtualenv -p python3 build-env 
    Run . build-env/bin/activate 
    Run pip install pip --upgrade 
    Run pip install jinja2 
    Run pip install requests 
    Run pip install gcovr 
    Run pip install conan
    # until everything in merged in master
    #Run pip install git+https://bitbucket.org/sconsparts/parts.git 
    Run pip install scons-parts
else
    Log "Setting up python virtualenv"
    Run . build-env/bin/activate 
fi

# just run the command as it is fast given the cache is setup already

Log "Setting setting up cmake3"
Run conan install cmake_installer/3.14.3@conan/stable -g virtualrunenv --build cmake_installer
Run source ./activate_run.sh

# have to reenable this as it get removed by a step above
if [ -f /opt/rh/httpd24/enable ]; then
    . /opt/rh/httpd24/enable 
fi

unset Verbose

