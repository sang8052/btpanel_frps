#!/bin/bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

#配置插件安装目录
install_path=/www/server/panel/plugin/frps

#安装
Install()
{
	
	echo '正在安装...'
	#==================================================================

  	#依赖安装开始
  echo 'IW3C 已经更名为南京无调网络工作室,无调云官网即将上线,尽情期待...'
  echo 'https://cdn.iw3c.com.cn 为本插件提供CDN 支持'

  echo '[NOTICE]:FRP 服务端插件已经正式修改包名为frps'

  #安装插件的logo

  rm -rf /www/server/panel/BTPanel/static/img/soft_ico/ico-frps.png
  cp $install_path/icon.png /www/server/panel/BTPanel/static/img/soft_ico/ico-frps.png
  # 初始化插件
  btpython $install_path/frps_main.py init

  # 安装frp 内核
  echo '==================================================='
  echo '即将开始安装 frp 最新版本内核,部分国外节点可能需要较长时间...'
  btpython $install_path/frps_main.py install last_version
  echo 'frp 最新内核安装完成'
  echo '===================================================='

  server_ip=$(curl https://ip.iw3c.top)
  echo '==================================================='
  echo "当前服务器的公网ip地址是${server_ip}"
  echo '开始生成服务器TLS 自签名证书'
  echo "CN:  ${server_ip}.frp.plugin.bt.cn"
  echo "IP:  ${server_ip}"
  echo "DNS: ${server_ip}.frp.plugin.bt.cn"
  echo '===================================================='

  sleep 3

  # 重新生成证书文件
  if [ ! -f "${install_path}/data/tls/ca/ca.key" ];then
    mkdir ${install_path}/data/tls/ca/
    mkdir ${install_path}/data/tls/server/
    echo '生成服务器CA 证书中'
    # centos 的 openssl.cnf 文件地址 /etc/pki/tls/openssl.cnf
    # ubuntu 的 openssl.cnf 文件地址 usr/lib/ssl/openssl.cnf
    if [ ! -f /etc/pki/tls/openssl.cnf ];then
        cp /etc/pki/tls/openssl.cnf $install_path/data/tls/openssl.cnf
    else:
        cp /usr/lib/ssl/openssl.cnf $install_path/data/tls/openssl.cnf
    fi
    openssl genrsa -out $install_path/data/tls/ca/ca.key 2048
    openssl req -x509 -new -nodes -key $install_path/data/tls/ca/ca.key -subj "/CN=${server_ip}.frp.plugin.bt.cn" -days 5000 -out $install_path/data/tls/ca/ca.crt
    echo '生成服务器证书中'
    openssl genrsa -out $install_path/data/tls/server/server.key 2048
    openssl req -new -sha256 -key $install_path/data/tls/server/server.key -subj  "/C=XX/ST=DEFAULT/L=DEFAULT/O=DEFAULT/CN=${server_ip}.frp.plugin.bt.cn" \
      -reqexts SAN      -config <(cat $install_path/data/tls/openssl.cnf <(printf "\n[SAN]\nsubjectAltName=DNS:localhost,IP:${server_ip},DNS:${server_ip}.frp.plugin.bt.cn")) \
     -out $install_path/data/tls/server/server.csr
    openssl x509 -req -days 5000 -in $install_path/data/tls/server/server.csr -CA $install_path/data/tls/ca/ca.crt -CAkey $install_path/data/tls/ca/ca.key -CAcreateserial \
	    -extfile <(printf "subjectAltName=DNS:localhost,IP:${server_ip},DNS:server.${server_ip}.frp.plugin.bt.cn") \
	    -out $install_path/data/tls/server/server.crt
  fi

  echo 'TLS 自签名证书生成成功'
  echo "证书路径地址:"
  echo "[1] CA 证书     ${install_path}/data/tls/ca/"
  echo "[2] 服务端证书   ${install_path}/data/tls/server/"
  echo "本证书仅共 frps 和 frpc 在通讯过程中加密使用,非网站SSL 证书,敬请知悉!"
  echo "插件自动生成的 TLS 证书不包含您的隐私信息,请勿[修改/移动/删除] 证书!"

  # 生成证书文件成功

  cp $install_path/error.html $install_path/data/conf/error.html

  sed -i '/frps_main.py/d' /etc/rc.d/rc.local && chmod +x /etc/rc.d/rc.local
  echo "btpython /www/server/panel/plugin/frpc/frps_main.py start" >> /etc/rc.d/rc.local && chmod +x /etc/rc.d/rc.local
	echo '================================================'
	echo '安装完成'
}

#卸载
Uninstall()
{
  btpython $install_path/frps_main.py stop
  sed -i '/frps_main.py/d' /etc/rc.d/rc.local && chmod +x /etc/rc.d/rc.local
	rm -rf $install_path
}

#操作判断
if [ "${1}" == 'install' ];then
	Install
elif [ "${1}" == 'uninstall' ];then
	Uninstall
else
	echo 'Error!';
fi
