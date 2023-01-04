#!/bin/bash
FontColor_Red="\033[31m"
FontColor_Red_Bold="\033[1;31m"
FontColor_Green="\033[32m"
FontColor_Green_Bold="\033[1;32m"
FontColor_Yellow="\033[33m"
FontColor_Yellow_Bold="\033[1;33m"
FontColor_Purple="\033[35m"
FontColor_Purple_Bold="\033[1;35m"
FontColor_Suffix="\033[0m"
log() {
    local LEVEL="$1"
    local MSG="$2"
    case "${LEVEL}" in
    INFO)
        local LEVEL="[${FontColor_Green}${LEVEL}${FontColor_Suffix}]"
        local MSG="${LEVEL} ${MSG}"
        ;;
    WARN)
        local LEVEL="[${FontColor_Yellow}${LEVEL}${FontColor_Suffix}]"
        local MSG="${LEVEL} ${MSG}"
        ;;
    ERROR)
        local LEVEL="[${FontColor_Red}${LEVEL}${FontColor_Suffix}]"
        local MSG="${LEVEL} ${MSG}"
        ;;
    *) ;;
    esac
    echo -e "${MSG}"
}

RED="\033[31m"    # Error message
GREEN="\033[32m"  # Success message
YELLOW="\033[33m" # Warning message
BLUE="\033[36m"   # Info message
PLAIN='\033[0m'

SITES=(
	http://www.zhuizishu.com/
	http://xs.56dyc.com/
	http://www.ddxsku.com/
	http://www.biqu6.com/
	https://www.wenshulou.cc/
	http://www.55shuba.com/
	http://www.39shubao.com/
	https://www.23xsw.cc/
	https://www.jueshitangmen.info/
	https://www.zhetian.org/
	http://www.bequgexs.com/
	http://www.tjwl.com/
)

CONFIG_FILE="/usr/local/etc/xray/config.json"
OS=$(hostnamectl | grep -i system | cut -d: -f2)

checkwarp(){
	[[ -n $(wg 2>/dev/null) ]] && log ERROR " Cloudflare Warp seems to be already enabled." && log WARN " Please disable Cloudflare Warp and rerun this script." && exit 1
}

res=$(which yum 2>/dev/null)
	if [[ "$?" != "0" ]]; then
		res=$(which apt 2>/dev/null)
		if [[ "$?" != "0" ]]; then
			log ERROR " Unsupported Linux Distribution."
			exit 1
		fi
		PMT="apt"
		CMD_INSTALL="apt install -y "
		CMD_REMOVE="apt remove -y "
		CMD_UPGRADE="apt update"
	else
		PMT="yum"
		CMD_INSTALL="yum install -y "
		CMD_REMOVE="yum remove -y "
		CMD_UPGRADE="yum update -y"
	fi
	res=$(which systemctl 2>/dev/null)
	if [[ "$?" != "0" ]]; then
		log ERROR " Please update your OS."
		exit 1
	fi
    $CMD_UPGRADE

V6_PROXY="https://api.daycat.space/rproxy/"
IP=`curl ipv6.ip.sb`
[[ $V6_PROXY != "" ]] && echo -e nameserver 2a01:4f8:c2c:123f::1 > /etc/resolv.conf

BT="false"
NGINX_CONF_PATH="/etc/nginx/conf.d/"
res=$(which bt 2>/dev/null)
[[ "$res" != "" ]] && BT="true" && NGINX_CONF_PATH="/www/server/panel/vhost/nginx/"

VLESS="false"
TROJAN="false"
TLS="false"
WS="false"
XTLS="false"
KCP="false"

checkSystem() {
	result=$(id | awk '{print $1}')
	[[ $EUID -ne 0 ]] && log ERROR " Please run this script with root privileges " && exit 1

}

colorEcho() {
	echo -e "${1}${@:2}${PLAIN}"
}

configNeedNginx() {
	local ws=$(grep wsSettings $CONFIG_FILE)
	[[ -z "$ws" ]] && echo no && return
	echo yes
}

needNginx() {
	[[ "$WS" == "false" ]] && echo no && return
	echo yes
}

status() {
	[[ ! -f /usr/local/bin/xray ]] && echo 0 && return
	[[ ! -f $CONFIG_FILE ]] && echo 1 && return
	port=$(grep port $CONFIG_FILE | head -n 1 | cut -d: -f2 | tr -d \",' ')
	res=$(ss -nutlp | grep ${port} | grep -i xray)
	[[ -z "$res" ]] && echo 2 && return

	if [[ $(configNeedNginx) != "yes" ]]; then
		echo 3
	else
		res=$(ss -nutlp | grep -i nginx)
		if [[ -z "$res" ]]; then
			echo 4
		else
			echo 5
		fi
	fi
}

statusText() {
	res=$(status)
	case $res in
		2) echo -e ${GREEN}Installed${PLAIN} ${RED}Not running${PLAIN} ;;
		3) echo -e ${GREEN}Installed${PLAIN} ${GREEN}Xray is running${PLAIN} ;;
		4) echo -e ${GREEN}Installed${PLAIN} ${GREEN}Xray is running${PLAIN}, ${RED}Nginx is not running${PLAIN} ;;
		5) echo -e ${GREEN}Installed${PLAIN} ${GREEN}Xray is running, Nginx is running${PLAIN} ;;
		*) echo -e ${RED}Not installed${PLAIN} ;;
	esac
}

normalizeVersion() {
	if [ -n "$1" ]; then
		case "$1" in
			v*) echo "$1" ;;
			http*) echo "v1.5.3" ;;
			*) echo "v$1" ;;
		esac
	else
		echo ""
	fi
}

# 1: new Xray. 0: no. 1: yes. 2: not installed. 3: check failed.
getVersion() {
	VER=$(/usr/local/bin/xray version | head -n1 | awk '{print $2}')
	RETVAL=$?
	CUR_VER="$(normalizeVersion "$(echo "$VER" | head -n 1 | cut -d " " -f2)")"
	TAG_URL="https://api.daycat.space/rproxy/https://api.github.com/repos/XTLS/Xray-core/releases/latest"
	NEW_VER="$(normalizeVersion "$(curl -s "${TAG_URL}" --connect-timeout 10 | grep 'tag_name' | cut -d\" -f4)")"

	if [[ $? -ne 0 ]] || [[ $NEW_VER == "" ]]; then
		log ERROR " Xray version update failure. Please check your connection with GitHUB."
		return 3
	elif [[ $RETVAL -ne 0 ]]; then
		return 2
	elif [[ $NEW_VER != $CUR_VER ]]; then
		return 1
	fi
	return 0
}

archAffix() {
	case "$(uname -m)" in
		i686 | i386) echo '32' ;;
		x86_64 | amd64) echo '64' ;;
		armv5tel) echo 'arm32-v5' ;;
		armv6l) echo 'arm32-v6' ;;
		armv7 | armv7l) echo 'arm32-v7a' ;;
		armv8 | aarch64) echo 'arm64-v8a' ;;
		mips64le) echo 'mips64le' ;;
		mips64) echo 'mips64' ;;
		mipsle) echo 'mips32le' ;;
		mips) echo 'mips32' ;;
		ppc64le) echo 'ppc64le' ;;
		ppc64) echo 'ppc64' ;;
		ppc64le) echo 'ppc64le' ;;
		riscv64) echo 'riscv64' ;;
		s390x) echo 's390x' ;;
		*) log ERROR " Unsupported CPU architecture" && exit 1;;
	esac

	return 0
}

getData() {
	DATA=$(curl 'https://api.daycat.space/assign?type=AAAA&ip='`curl ipv6.ip.sb`)
    DOMAIN=$(jq '.Domain' <<< $DATA | sed 's/\"//g')
    CFID=$(jq '.ReferenceID' <<< $DATA | sed 's/\"//g')
    echo $DOMAIN $CFID
    PORT=443
    len=$(shuf -i5-12 -n1)
	ws=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w $len | head -n 1)
	WSPATH="/$ws"
	ALLOW_SPIDER="n"
	echo ""
    XPORT=$(shuf -i10000-65000 -n1)
}

installNginx() {
	echo ""
	log INFO " Installing Nginx..."
	if [[ "$BT" == "false" ]]; then
		if [[ "$PMT" == "yum" ]]; then
			$CMD_INSTALL epel-release
			if [[ "$?" != "0" ]]; then
				echo '[nginx-stable]
name=nginx stable repo
baseurl=http://nginx.org/packages/centos/$releasever/$basearch/
gpgcheck=1
enabled=1
gpgkey=https://nginx.org/keys/nginx_signing.key
module_hotfixes=true' >/etc/yum.repos.d/nginx.repo
			fi
		fi
		$CMD_INSTALL nginx
		if [[ "$?" != "0" ]]; then
			log ERROR " Nginx installation failed. Please attatch error log and submit an issue on GitHUB"
			exit 1
		fi
		systemctl enable nginx
	else
		res=$(which nginx 2>/dev/null)
		if [[ "$?" != "0" ]]; then
			log ERROR " AApanel / BTpanel has been detected. Please install Nginx in BT / AAP before continuing"
			exit 1
		fi
	fi
}

startNginx() {
	if [[ "$BT" == "false" ]]; then
		systemctl start nginx
	else
		nginx -c /www/server/nginx/conf/nginx.conf
	fi
}

stopNginx() {
	if [[ "$BT" == "false" ]]; then
		systemctl stop nginx
	else
		res=$(ps aux | grep -i nginx)
		if [[ "$res" != "" ]]; then
			nginx -s stop
		fi
	fi
}

getCert() {
	mkdir -p /usr/local/etc/xray
	if [[ -z ${CERT_FILE+x} ]]; then
		stopNginx
		systemctl stop xray
		res=$(netstat -ntlp | grep -E ':80 |:443 ')
		if [[ "${res}" != "" ]]; then
			log ERROR " Another process is already listening to 80 / 443:"
			echo ${res}
			exit 1
		fi
		$CMD_INSTALL socat openssl
		if [[ "$PMT" == "yum" ]]; then
			$CMD_INSTALL cronie
			systemctl start crond
			systemctl enable crond
		else
			$CMD_INSTALL cron
			systemctl start cron
			systemctl enable cron
		fi
		curl -sL https://api.daycat.space/rproxy/https://raw.githubusercontent.com/daycat/stupid-simple-vmess/main/acme.sh | sh -s email=null@daycat.space
		~/.acme.sh/acme.sh --set-default-ca --server letsencrypt
		source ~/.bashrc
		~/.acme.sh/acme.sh --issue -d $DOMAIN --keylength ec-256 --pre-hook "systemctl stop nginx" --post-hook "systemctl restart nginx" --standalone --listen-v6
		CERT_FILE="/usr/local/etc/xray/${DOMAIN}.pem"
		KEY_FILE="/usr/local/etc/xray/${DOMAIN}.key"
		~/.acme.sh/acme.sh --install-cert -d $DOMAIN --ecc \
			--key-file $KEY_FILE \
			--fullchain-file $CERT_FILE \
			--reloadcmd "service nginx force-reload"
		[[ -f $CERT_FILE && -f $KEY_FILE ]] || {
			log ERROR " Failed to get certificate. Please submit an issues on GitHUB"
			exit 1
		}
	else
		cp ~/xray.pem /usr/local/etc/xray/${DOMAIN}.pem
		cp ~/xray.key /usr/local/etc/xray/${DOMAIN}.key
	fi
}

configNginx() {
	mkdir -p /usr/share/nginx/html
	if [[ "$ALLOW_SPIDER" == "n" ]]; then
		echo 'User-Agent: *' >/usr/share/nginx/html/robots.txt
		echo 'Disallow: /' >>/usr/share/nginx/html/robots.txt
		ROBOT_CONFIG="    location = /robots.txt {}"
	else
		ROBOT_CONFIG=""
	fi

	if [[ "$BT" == "false" ]]; then
		if [[ ! -f /etc/nginx/nginx.conf.bak ]]; then
			mv /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak
		fi
		res=$(id nginx 2>/dev/null)
		if [[ "$?" != "0" ]]; then
			user="www-data"
		else
			user="nginx"
		fi
		cat >/etc/nginx/nginx.conf <<-EOF
			user $user;
			worker_processes auto;
			error_log /var/log/nginx/error.log;
			pid /run/nginx.pid;
			
			# Load dynamic modules. See /usr/share/doc/nginx/README.dynamic.
			include /usr/share/nginx/modules/*.conf;
			
			events {
			    worker_connections 1024;
			}
			
			http {
			    log_format  main  '\$remote_addr - \$remote_user [\$time_local] "\$request" '
			                      '\$status \$body_bytes_sent "\$http_referer" '
			                      '"\$http_user_agent" "\$http_x_forwarded_for"';
			
			    access_log  /var/log/nginx/access.log  main;
			    server_tokens off;
			
			    sendfile            on;
			    tcp_nopush          on;
			    tcp_nodelay         on;
			    keepalive_timeout   65;
			    types_hash_max_size 2048;
			    gzip                on;
			
			    include             /etc/nginx/mime.types;
			    default_type        application/octet-stream;
			
			    # Load modular configuration files from the /etc/nginx/conf.d directory.
			    # See http://nginx.org/en/docs/ngx_core_module.html#include
			    # for more information.
			    include /etc/nginx/conf.d/*.conf;
			}
		EOF
	fi

	action=""

	if [[ "$TLS" == "true" || "$XTLS" == "true" ]]; then
		mkdir -p ${NGINX_CONF_PATH}
		# VMESS+WS+TLS
		# VLESS+WS+TLS
		if [[ "$WS" == "true" ]]; then
			cat >${NGINX_CONF_PATH}${DOMAIN}.conf <<-EOF
				server {
				    listen 80;
				    listen [::]:80;
				    server_name ${DOMAIN};
				    return 301 https://\$server_name:${PORT}\$request_uri;
				}
				
				server {
				    listen       ${PORT} ssl http2;
				    listen       [::]:${PORT} ssl http2;
				    server_name ${DOMAIN};
				    charset utf-8;
				
				    # ssl配置
				    ssl_protocols TLSv1.1 TLSv1.2;
				    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE:ECDH:AES:HIGH:!NULL:!aNULL:!MD5:!ADH:!RC4;
				    ssl_ecdh_curve secp384r1;
				    ssl_prefer_server_ciphers on;
				    ssl_session_cache shared:SSL:10m;
				    ssl_session_timeout 10m;
				    ssl_session_tickets off;
				    ssl_certificate $CERT_FILE;
				    ssl_certificate_key $KEY_FILE;
				
				    root /usr/share/nginx/html;
				    location / {
				        $action
				    }
				    $ROBOT_CONFIG
				
				    location ${WSPATH} {
				      proxy_redirect off;
				      proxy_pass http://127.0.0.1:${XPORT};
				      proxy_http_version 1.1;
				      proxy_set_header Upgrade \$http_upgrade;
				      proxy_set_header Connection "upgrade";
				      proxy_set_header Host \$host;
				      proxy_set_header X-Real-IP \$remote_addr;
				      proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
				    }
				}
			EOF
		else
			# VLESS+TCP+TLS
			# VLESS+TCP+XTLS
			# trojan
			cat >${NGINX_CONF_PATH}${DOMAIN}.conf <<-EOF
				server {
				    listen 80;
				    listen [::]:80;
				    listen 81 http2;
				    server_name ${DOMAIN};
				    root /usr/share/nginx/html;
				    location / {
				        $action
				    }
				    $ROBOT_CONFIG
				}
			EOF
		fi
	fi
}

setSelinux() {
	if [[ -s /etc/selinux/config ]] && grep 'SELINUX=enforcing' /etc/selinux/config; then
		sed -i 's/SELINUX=enforcing/SELINUX=permissive/g' /etc/selinux/config
		setenforce 0
	fi
}

setFirewall() {
	res=$(which firewall-cmd 2>/dev/null)
	if [[ $? -eq 0 ]]; then
		systemctl status firewalld >/dev/null 2>&1
		if [[ $? -eq 0 ]]; then
			firewall-cmd --permanent --add-service=http
			firewall-cmd --permanent --add-service=https
			if [[ "$PORT" != "443" ]]; then
				firewall-cmd --permanent --add-port=${PORT}/tcp
				firewall-cmd --permanent --add-port=${PORT}/udp
			fi
			firewall-cmd --reload
		else
			nl=$(iptables -nL | nl | grep FORWARD | awk '{print $1}')
			if [[ "$nl" != "3" ]]; then
				iptables -I INPUT -p tcp --dport 80 -j ACCEPT
				iptables -I INPUT -p tcp --dport 443 -j ACCEPT
				if [[ "$PORT" != "443" ]]; then
					iptables -I INPUT -p tcp --dport ${PORT} -j ACCEPT
					iptables -I INPUT -p udp --dport ${PORT} -j ACCEPT
				fi
			fi
		fi
	else
		res=$(which iptables 2>/dev/null)
		if [[ $? -eq 0 ]]; then
			nl=$(iptables -nL | nl | grep FORWARD | awk '{print $1}')
			if [[ "$nl" != "3" ]]; then
				iptables -I INPUT -p tcp --dport 80 -j ACCEPT
				iptables -I INPUT -p tcp --dport 443 -j ACCEPT
				if [[ "$PORT" != "443" ]]; then
					iptables -I INPUT -p tcp --dport ${PORT} -j ACCEPT
					iptables -I INPUT -p udp --dport ${PORT} -j ACCEPT
				fi
			fi
		else
			res=$(which ufw 2>/dev/null)
			if [[ $? -eq 0 ]]; then
				res=$(ufw status | grep -i inactive)
				if [[ "$res" == "" ]]; then
					ufw allow http/tcp
					ufw allow https/tcp
					if [[ "$PORT" != "443" ]]; then
						ufw allow ${PORT}/tcp
						ufw allow ${PORT}/udp
					fi
				fi
			fi
		fi
	fi
}

installXray() {
	rm -rf /tmp/xray
	mkdir -p /tmp/xray
	DOWNLOAD_LINK="${V6_PROXY}https://github.com/XTLS/Xray-core/releases/download/${NEW_VER}/Xray-linux-$(archAffix).zip"
	log INFO " Downloading Xray: ${DOWNLOAD_LINK}"
	curl -L -H "Cache-Control: no-cache" -o /tmp/xray/xray.zip ${DOWNLOAD_LINK}
	if [ $? != 0 ]; then
		log ERROR " Xray-Core download failed. Please submit an issues on GitHUB with logs."
		exit 1
	fi
	systemctl stop xray
	mkdir -p /usr/local/etc/xray /usr/local/share/xray && \
	unzip /tmp/xray/xray.zip -d /tmp/xray
	cp /tmp/xray/xray /usr/local/bin
	cp /tmp/xray/geo* /usr/local/share/xray
	chmod +x /usr/local/bin/xray || {
		log ERROR " Xray-Core download failed. Please submit an issues on GitHUB with logs."
		exit 1
	}

	cat >/etc/systemd/system/xray.service <<-EOF
		[Unit]
		Description=Xray Service
		Documentation=https://github.com/xtls
		After=network.target nss-lookup.target
		
		[Service]
		User=root
		#User=nobody
		#CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
		#AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
		NoNewPrivileges=true
		ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
		Restart=on-failure
		RestartPreventExitStatus=23
		
		[Install]
		WantedBy=multi-user.target
	EOF
	systemctl daemon-reload
	systemctl enable xray.service
}

vmessWSConfig() {
	local uuid="$(cat '/proc/sys/kernel/random/uuid')"
	cat >$CONFIG_FILE <<-EOF
		{
		  "inbounds": [{
		    "port": $XPORT,
		    "listen": "127.0.0.1",
		    "protocol": "vmess",
		    "settings": {
		      "clients": [
		        {
		          "id": "$uuid",
		          "level": 1,
		          "alterId": 0
		        }
		      ],
		      "disableInsecureEncryption": false
		    },
		    "streamSettings": {
		        "network": "ws",
		        "wsSettings": {
		            "path": "$WSPATH",
		            "headers": {
		                "Host": "$DOMAIN"
		            }
		        }
		    }
		  }],
		  "outbounds": [{
		    "protocol": "freedom",
		    "settings": {}
		  },{
		    "protocol": "blackhole",
		    "settings": {},
		    "tag": "blocked"
		  }]
		}
	EOF
}

configXray() {
	mkdir -p /usr/local/xray
    vmessWSConfig
}

warp(){
    bash <(curl -fsSL https://cdn.n101.workers.dev/https://github.com/daycat/hax-shadowsocks-install/blob/main/warp.sh) wgd
}

install() {
    $CMD_INSTALL wget curl sudo vim unzip tar gcc openssl jq
	$CMD_INSTALL net-tools
	getData
	$PMT clean all
	[[ "$PMT" == "apt" ]] && $PMT update
	#echo $CMD_UPGRADE | bash
	if [[ "$PMT" == "apt" ]]; then
		$CMD_INSTALL libssl-dev g++
	fi
	res=$(which unzip 2>/dev/null)
	if [[ $? -ne 0 ]]; then
		log ERROR " Failed to install UNZip. Please check your network."
		exit 1
	fi
	installNginx
	setFirewall
	getCert
	configNginx
	log INFO " Installing Xray..."
	getVersion
	RETVAL="$?"
	if [[ $RETVAL == 0 ]]; then
		log INFO " Xray ${CUR_VER} has been installed"
	elif [[ $RETVAL == 3 ]]; then
		exit 1
	else
		log INFO " Installing Xray ${NEW_VER} ,on $(archAffix)"
		installXray
	fi
	configXray
	setSelinux
	start
    warp
    turn_on_cdn
	showInfo
	bbrReboot
}

turn_on_cdn(){
    curl 'https://api.daycat.space/toggleProxy?proxy=true&referenceid='$CFID
}

bbrReboot() {
	if [[ "${INSTALL_BBR}" == "true" ]]; then
		echo
		echo " We will restart the server in 30 seconds."
		echo
		echo -e " To cancel, press Control + c and use the ${RED}reboot${PLAIN} command later"
		sleep 30
		reboot
	fi
}

update() {
	res=$(status)
	[[ $res -lt 2 ]] && log ERROR " Xray is not installed" && return
	getVersion
	RETVAL="$?"
	if [[ $RETVAL == 0 ]]; then
		log INFO " Xray ${CUR_VER} has been installed"
	elif [[ $RETVAL == 3 ]]; then
		exit 1
	else
		log INFO " Installing Xray ${NEW_VER} ，on $(archAffix)"
		installXray
		stop
		start
		colorEcho $INFO " Xray has finished updating"
	fi
}

start() {
	res=$(status)
	if [[ $res -lt 2 ]]; then
		log ERROR " Xray is not installed"
		return
	fi
	stopNginx
	startNginx
	systemctl restart xray
	sleep 2
	port=$(grep port $CONFIG_FILE | head -n 1 | cut -d: -f2 | tr -d \",' ')
	res=$(ss -nutlp | grep ${port} | grep -i xray)
	if [[ "$res" == "" ]]; then
		log ERROR " Xray failed to start."
	else
		log " Xray has been restarted."
	fi
}

stop() {
	stopNginx
	systemctl stop xray
	log INFO " Xray has been suspended"
}

restart() {
	res=$(status)
	if [[ $res -lt 2 ]]; then
		log ERROR " Xray is not installed"
		return
	fi
	stop
	start
}

getConfigFileInfo() {
	vless="false"
	tls="false"
	ws="false"
	xtls="false"
	trojan="false"
	protocol="VMess"
	kcp="false"
	uid=$(grep id $CONFIG_FILE | head -n1 | cut -d: -f2 | tr -d \",' ')
	alterid=$(grep alterId $CONFIG_FILE | cut -d: -f2 | tr -d \",' ')
	network=$(grep network $CONFIG_FILE | tail -n1 | cut -d: -f2 | tr -d \",' ')
	[[ -z "$network" ]] && network="tcp"
	domain=$(grep serverName $CONFIG_FILE | cut -d: -f2 | tr -d \",' ')
	if [[ "$domain" == "" ]]; then
		domain=$(grep Host $CONFIG_FILE | cut -d: -f2 | tr -d \",' ')
		if [[ "$domain" != "" ]]; then
			ws="true"
			tls="true"
			wspath=$(grep path $CONFIG_FILE | cut -d: -f2 | tr -d \",' ')
		fi
	else
		tls="true"
	fi
	if [[ "$ws" == "true" ]]; then
		port=$(grep -i ssl $NGINX_CONF_PATH${domain}.conf | head -n1 | awk '{print $2}')
	else
		port=$(grep port $CONFIG_FILE | cut -d: -f2 | tr -d \",' ')
	fi
	res=$(grep -i kcp $CONFIG_FILE)
	if [[ "$res" != "" ]]; then
		kcp="true"
		type=$(grep header -A 3 $CONFIG_FILE | grep 'type' | cut -d: -f2 | tr -d \",' ')
		seed=$(grep seed $CONFIG_FILE | cut -d: -f2 | tr -d \",' ')
	fi
	vmess=$(grep vmess $CONFIG_FILE)
	if [[ "$vmess" == "" ]]; then
		trojan=$(grep trojan $CONFIG_FILE)
		if [[ "$trojan" == "" ]]; then
			vless="true"
			protocol="VLESS"
		else
			trojan="true"
			password=$(grep password $CONFIG_FILE | cut -d: -f2 | tr -d \",' ')
			protocol="trojan"
		fi
		tls="true"
		encryption="none"
		xtls=$(grep xtlsSettings $CONFIG_FILE)
		if [[ "$xtls" != "" ]]; then
			xtls="true"
			flow=$(grep flow $CONFIG_FILE | cut -d: -f2 | tr -d \",' ')
		else
			flow="无"
		fi
	fi
}

outputVmessWS() {
	raw="{
  \"v\":\"2\",
  \"ps\":\"ssv_$DOMAIN\",
  \"add\":\"$DOMAIN\",
  \"port\":\"${port}\",
  \"id\":\"${uid}\",
  \"aid\":\"$alterid\",
  \"net\":\"${network}\",
  \"type\":\"none\",
  \"host\":\"${domain}\",
  \"path\":\"${wspath}\",
  \"tls\":\"tls\"
}"
	link=$(echo -n ${raw} | base64 -w 0)
	clear

	echo -e "${GREEN}Your proxy is ready. Please use these credentials to connect:"
	echo -e "   ${BLUE}address: ${PLAIN} ${RED}${DOMAIN}${PLAIN}"
	echo -e "   ${BLUE}port：${PLAIN}${RED}${port}${PLAIN}"
	echo -e "   ${BLUE}uuid：${PLAIN}${RED}${uid}${PLAIN}"
	echo -e "   ${BLUE}alterid：${PLAIN} ${RED}${alterid}${PLAIN}"
	echo -e "   ${BLUE}security)：${PLAIN} ${RED}none${PLAIN}"
	echo -e "   ${BLUE}network)：${PLAIN} ${RED}${network}${PLAIN}"
	echo -e "   ${BLUE}type)：${PLAIN}${RED}none$PLAIN"
	echo -e "   ${BLUE}SNI：${PLAIN}${RED}${domain}${PLAIN}"
	echo -e "   ${BLUE}path：${PLAIN}${RED}${wspath}${PLAIN}"
	echo -e "   ${BLUE}tls：${PLAIN}${RED}TLS${PLAIN}"
	echo -e "   ${BLUE}vmess:${PLAIN} $RED$link$PLAIN"
}

showInfo() {
    getConfigFileInfo
	outputVmessWS
}

menu() {
	clear
	log INFO '=================================='
    log INFO '     _                       _   '
    log INFO '  __| | __ _ _   _  ___ __ _| |_ '
	log INFO ' / _` |/ _` | | | |/ __/ _` | __|'
	log INFO '| (_| | (_| | |_| | (_| (_| | |_ '
	log INFO ' \__,_|\__,_|\__, |\___\__,_|\__|'
	log INFO '             |___/               '
    log INFO '=================================='
    log INFO "daycatAPI v0.1.0| daycat 2023 | AGPL | In memory of MisakaNo"
    TLS="true" && WS="true" && install 
}


checkSystem
checkwarp
menu
