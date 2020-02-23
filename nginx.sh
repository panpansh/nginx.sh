#!/bin/bash
# set to y to make a new working project
MAKE_NEW_FORK="n"
# set y to clone and update moddules
NEED_MODULES_CLONE_AND_UPDATE="y"
# rewrite deb rules to update it
REWRITE_DEB_RULES="y"
# install src libs dependencies like modsecurity sregex
INSTALL_SRC_LIBS="y"
# install apt packages dependencies
INSTALL_APT_LIBS="y"
# build packages for src libs
MAKE_PKG_SRC_LIBS="n"
if [[ "$MAKE_NEW_FORK" = 'y' ]]; then
    REWRITE_DEB_RULES="y"
    NEED_MODULES_CLONE_AND_UPDATE="y"
    INSTALL_SRC_LIBS="y"
fi
# set yes to build apash3pack
QUICHE="n"
# need patch
QUICHE_GIT="https://github.com/cloudflare/quiche.git"
QUICHE_BRANCH="master"
QUICHE_CHECKOUT="9d1417836e81ae61383b175355f13224224976b8"

export PATH=$PATH:/sbin:/usr/sbin

export PHP_CONFIG=/usr/bin/php-config
export PHP_BIN=/usr/bin/php
export PHP_INC=/usr/include/php
export PHP_LIB=/usr/lib/php

NGBUILD_PATH="/apash"
NGINX_VERSION="nginx-1.16.1"
V_COMPONENT="16x.00.01"
COMPONENT="apashpack"
if [[ "$QUICHE" = 'y' ]]; then
    COMPONENT="apash3pack"
fi
MOD_DIR_NAME="src_mod"
NG_APASH_VERSION_NAME="$V_COMPONENT$COMPONENT"
NG_WORKING_DIR="$NGBUILD_PATH/$NG_APASH_VERSION_NAME"

NG_SRC_PATH="$NG_WORKING_DIR/$NGINX_VERSION"
NG_MOD_PATH="$NG_SRC_PATH/$MOD_DIR_NAME"

NG_APASH_CONFIG_DIR_NAME="apash_config"
NG_APASH_CONFIG_PATH="$NG_MOD_PATH/$NG_APASH_CONFIG_DIR_NAME"

# check if directory exist before forking
if [ -d "$NG_WORKING_DIR" ]; then
    if [[ "$MAKE_NEW_FORK" = 'y' ]]; then
        echo -e "EXIST: $NG_WORKING_DIR"
        echo -e "please increment to make a new fork"
        exit 1
    fi
fi

#######################################################
###                MODULES SELECTION                ###
#######################################################
# modules to build with
OPENSSL="y"
if [[ "$QUICHE" = 'y' ]]; then
    OPENSSL="n"
    # Dependencies for BoringSSL and Quiche
    apt install -y golang cmake
    # Rust is not packaged so that's the only way...
    curl -sSf https://sh.rustup.rs | sh -s -- -y
    source $HOME/.cargo/env
fi
PAGESPEED="y"
NAXSI="y"
MODSECURITY="y"
BROTLI="y"
DEVKIT="y"
PHP7="y"
NJS="y"
AUTH_PAM="y"
AUTH_DIGEST="y"
COOKIE_FLAG="y"
AKAMAI_G2O="y"
CACHE_PURGE="y"
XSS="y"
ECHO="y"
EXECUTE="y"
ELASTIC="y"
ENCRYPTED_SESSION="y"
DYN_LIMIT_REQ="y"
FORM_INPUT="y"
GEOIP2="y"
TRAFFIC_ACC="y"
HEADERS_MORE="y"
IPSCRUB="y"
LOG_ZEROMQ="y"
LDAP="y"
MODJPEG="y"
MEMC="y"
NCHAN="y"
LINK_FUNCTION="y"
REPLACE_FILTER="y"
REDIS2="y"
RDNS="y"
PUSH_STREAM="y"
RTMP="y"
RTMPT_PROXY="y"
SEC_HEADERS="y"
SASS="y"
SORTED_QUERYSTRING="y"
SRCACHE="y"
UPSYNC="y"
STREAM_UPSYNC="y"
STS="y"
STREAM_STS="y"
VTS="y"
SYSGUARD="y"
TEST_COOKIE="y"
UPLOAD_PROGRESS="y"
VOD="y"
ZIP="y"
#######################################################
###             END OF MODULES SELECTION            ###
#######################################################

#######################################################
###               MODULES GIT DETAILS               ###
#######################################################
# openssl
OPENSSL_GIT="https://github.com/openssl/openssl.git"
OPENSSL_BRANCH="OpenSSL_1_1_1d"
OPENSSL_CHECKOUT="894da2fb7ed5d314ee5c2fc9fd2d9b8b74111596"
# pagespeed latest-stable v1.13.35.2-stable
PAGESPEED_GIT="https://github.com/apache/incubator-pagespeed-ngx.git"
PAGESPEED_BRANCH="master"
PAGESPEED_CHECKOUT="c69649ab0a3f95d97bdaa7695c9d3f4c43296d09"
# naxsi
NAXSI_GIT="https://github.com/nbs-system/naxsi.git"
NAXSI_BRANCH="master"
NAXSI_CHECKOUT="928106ad1683f174428d4f5e8779f1d47eb5829b"
NAXSI_RULES_GIT="https://github.com/nbs-system/naxsi-rules.git"
NAXSI_RULES_BRANCH="master"
NAXSI_RULES_CHECKOUT="a1e2c403482fae1a1b9d010b30932596ed7e704e"
# modsecurity
MODSEC_LIB_GIT="https://github.com/SpiderLabs/ModSecurity.git"
MODSEC_LIB_BRANCH="v3/master"
MODSEC_LIB_CHECKOUT="6624a18a4e7fd9881a7a9b435db3e481e8e986a5"
MODSEC_NGINX_GIT="https://github.com/SpiderLabs/ModSecurity-nginx.git"
MODSEC_NGINX_BRANCH="master"
MODSEC_NGINX_CHECKOUT="d7101e13685efd7e7c9f808871b202656a969f4b"
MODSEC_CRS_GIT="https://github.com/SpiderLabs/owasp-modsecurity-crs.git"
MODSEC_CRS_BRANCH="master"
MODSEC_CRS_CHECKOUT="d33d107f50fb0eb356152a99749e7c0d25325078"
# brotli
BROTLI_GIT="https://github.com/google/ngx_brotli.git"
BROTLI_BRANCH="master"
BROTLI_CHECKOUT="e505dce68acc190cc5a1e780a3b0275e39f160ca"
# devkit
DEVKIT_GIT="https://github.com/simplresty/ngx_devel_kit.git"
DEVKIT_BRANCH="master"
DEVKIT_CHECKOUT="a22dade76c838e5f377d58d007f65d35b5ce1df3"
# php7
PHP7_GIT="https://github.com/rryqszq4/ngx_php7.git"
PHP7_BRANCH="v0.0.22"
PHP7_CHECKOUT="17b1671166353fa0871571bebf13dfb8ec64d1cf"
# njs
NJS_GIT="https://github.com/nginx/njs.git"
NJS_BRANCH="0.3.7"
NJS_CHECKOUT="c57dc430d79af52755785b997efd1b7df1376f46"
# auth pam
AUTH_PAM_GIT="https://github.com/sto/ngx_http_auth_pam_module.git"
AUTH_PAM_BRANCH="master"
AUTH_PAM_CHECKOUT="d9286fc7b52e1a3584da2cb20423f912ec99169f"
# auth digest
AUTH_DIGEST_GIT="https://github.com/atomx/nginx-http-auth-digest.git"
AUTH_DIGEST_BRANCH="master"
AUTH_DIGEST_CHECKOUT="b3073ef3624ec0e590671399e7b8f31458218d2a"
# cookie flag
COOKIE_FLAG_GIT="https://github.com/AirisX/nginx_cookie_flag_module.git"
COOKIE_FLAG_BRANCH="master"
COOKIE_FLAG_CHECKOUT="c4ff449318474fbbb4ba5f40cb67ccd54dc595d4"
# akamai g2o
AKAMAI_G2O_GIT="https://github.com/kaltura/nginx_mod_akamai_g2o.git"
AKAMAI_G2O_BRANCH="master"
AKAMAI_G2O_CHECKOUT="fd3abd4a54db2dd00247c2d8d02747031c2241f4"
# cache purge
CACHE_PURGE_GIT="https://github.com/FRiCKLE/ngx_cache_purge.git"
CACHE_PURGE_BRANCH="master"
CACHE_PURGE_CHECKOUT="331fe43e8d9a3d1fa5e0c9fec7d3201d431a9177"
# xss
XSS_GIT="https://github.com/openresty/xss-nginx-module.git"
XSS_BRANCH="master"
XSS_CHECKOUT="6c41076ac066c30c96d70e86da5400ffd49a6186"
# echo sleep time exec ..
ECHO_GIT="https://github.com/openresty/echo-nginx-module.git"
ECHO_BRANCH="master"
ECHO_CHECKOUT="83e9fbbbcf7599fd81b4e1c3edd2d48df0430235"
# execute
EXECUTE_GIT="https://github.com/limithit/NginxExecute.git"
EXECUTE_BRANCH="master"
EXECUTE_CHECKOUT="16ee0042ce5757a8111f920d51fe2048c8539aa2"
# elastic
ELASTIC_GIT="https://github.com/Taymindis/nginx-elastic-client.git"
ELASTIC_BRANCH="master"
ELASTIC_CHECKOUT="dc66ab17ccf2d9a0de5b1b947bb8c162b79100f9"
# encrypted session
ENCRYPTED_SESSION_GIT="https://github.com/openresty/encrypted-session-nginx-module.git"
ENCRYPTED_SESSION_BRANCH="master"
ENCRYPTED_SESSION_CHECKOUT="a42c37118588833723935aa460b2dc2e3234f0b0"
# dynamic limit request
DYN_LIMIT_REQ_GIT="https://github.com/limithit/ngx_dynamic_limit_req_module.git"
DYN_LIMIT_REQ_BRANCH="master"
DYN_LIMIT_REQ_CHECKOUT="47c320ec30a14ef83bcb4ad8b055c9b3d4666334"
# form input
FORM_INPUT_GIT="https://github.com/calio/form-input-nginx-module.git"
FORM_INPUT_BRANCH="master"
FORM_INPUT_CHECKOUT="2c94e74671f006d1897de062b5c774f7e0e5ff74"
# geoip2
GEOIP2_GIT="https://github.com/leev/ngx_http_geoip2_module.git"
GEOIP2_BRANCH="master"
GEOIP2_CHECKOUT="5a83b6f958c67ea88d2899d0b3c2a5db8e36b211"
# traffic accounting
TRAFFIC_ACC_GIT="https://github.com/Lax/traffic-accounting-nginx-module.git"
TRAFFIC_ACC_BRANCH="master"
TRAFFIC_ACC_CHECKOUT="701e8f1fdb8bdad3b43397ec341a7f38ea581a62"
# headers more
HEADERS_MORE_GIT="https://github.com/openresty/headers-more-nginx-module.git"
HEADERS_MORE_BRANCH="master"
HEADERS_MORE_CHECKOUT="552e216a0da95c685d9db4f43e209c3f2a803e49"
# ipscrub
IPSCRUB_GIT="https://github.com/masonicboom/ipscrub.git"
IPSCRUB_BRANCH="master"
IPSCRUB_CHECKOUT="ecfb7dbcf568cfb2aebbdfd7e7834abc451fc25b"
# log ZeroMQ
LOG_ZEROMQ_GIT="https://github.com/alticelabs/nginx-log-zmq.git"
LOG_ZEROMQ_BRANCH="master"
LOG_ZEROMQ_CHECKOUT="b8e18592491c8c9c2a4aae4a2f3eec377f753610"
# ldap
LDAP_GIT="https://github.com/kvspb/nginx-auth-ldap.git"
LDAP_BRANCH="master"
LDAP_CHECKOUT="e2081531c1eadd0afd9252e538c06f82c60db7f6"
# modjpeg
MODJPEG_LIB_GIT="https://github.com/ioppermann/libmodjpeg.git"
MODJPEG_LIB_BRANCH="master"
MODJPEG_LIB_CHECKOUT="8ba18bad40bb98d6ea3331d0e32bbe7bf1c1516f"
MODJPEG_GIT="https://github.com/ioppermann/modjpeg-nginx.git"
MODJPEG_BRANCH="master"
MODJPEG_CHECKOUT="162e458c6656165e125efaef5e6b033df0ae6752"
# memc
MEMC_GIT="https://github.com/openresty/memc-nginx-module.git"
MEMC_BRANCH="master"
MEMC_CHECKOUT="32124a5454238ca5ae78a8df9298445293e8d73c"
# nchan
NCHAN_GIT="https://github.com/slact/nchan.git"
NCHAN_BRANCH="master"
NCHAN_CHECKOUT="035e9226188b86f328e0afe07356551aa42c5eca"
# link function
LINK_FUNCTION_GIT="https://github.com/Taymindis/nginx-link-function.git"
LINK_FUNCTION_BRANCH="master"
LINK_FUNCTION_CHECKOUT="8375c898cc9c9b830281daa3f00892ebdf5b4191"
# replace filter
REPLACE_FILTER_SREGEX_GIT="https://github.com/openresty/sregex.git"
REPLACE_FILTER_SREGEX_BRANCH="master"
REPLACE_FILTER_SREGEX_CHECKOUT="c275d2291f5b7f1b3dea6b2c1f7818791360cca8"
REPLACE_FILTER_GIT="https://github.com/openresty/replace-filter-nginx-module.git"
REPLACE_FILTER_BRANCH="master"
REPLACE_FILTER_CHECKOUT="d66e1a5e241f650f534eb8fb639e2b1b9ad0d8a4"
# redis2
REDIS2_GIT="https://github.com/openresty/redis2-nginx-module.git"
REDIS2_BRANCH="master"
REDIS2_CHECKOUT="15b0c454c987599689c369c2dd4ef07f3d2bcaca"
# rdns
RDNS_GIT="https://github.com/flant/nginx-http-rdns.git"
RDNS_BRANCH="master"
RDNS_CHECKOUT="4946978a45c2ddf1cc19307f75464a7e0974ddc2"
# push stream
PUSH_STREAM_GIT="https://github.com/wandenberg/nginx-push-stream-module.git"
PUSH_STREAM_BRANCH="master"
PUSH_STREAM_CHECKOUT="723e5de7f0774fcaadb8f6fb555528e7aee160f2"
# rtmp
RTMP_GIT="https://github.com/arut/nginx-rtmp-module.git"
RTMP_BRANCH="master"
RTMP_CHECKOUT="791b6136f02bc9613daf178723ac09f4df5a3bbf"
# rtmp proxy
RTMPT_PROXY_GIT="https://github.com/kwojtek/nginx-rtmpt-proxy-module.git"
RTMPT_PROXY_BRANCH="master"
RTMPT_PROXY_CHECKOUT="5f3bb0c8ba4a0b9527da461052021c6b31a2d267"
# security headers
SEC_HEADERS_GIT="https://github.com/GetPageSpeed/ngx_security_headers.git"
SEC_HEADERS_BRANCH="master"
SEC_HEADERS_CHECKOUT="85c6018f6a300aa12da8e825d172e7819db0d569"
# sass
SASS_GIT="https://github.com/mneudert/sass-nginx-module.git"
SASS_BRANCH="master"
SASS_CHECKOUT="89d22bb86d50338d7d2d17420f2f726b98f3582e"
# sorted querystring
SORTED_QUERYSTRING_GIT="https://github.com/wandenberg/nginx-sorted-querystring-module.git"
SORTED_QUERYSTRING_BRANCH="master"
SORTED_QUERYSTRING_CHECKOUT="e5bbded07fd67e2977edc2bc145c45a7b3fc4d26"
# srcache
SRCACHE_GIT="https://github.com/openresty/srcache-nginx-module.git"
SRCACHE_BRANCH="master"
SRCACHE_CHECKOUT="daaa062237821177cf666c198162558f7deaad6d"
# upsync
UPSYNC_GIT="https://github.com/weibocom/nginx-upsync-module.git"
UPSYNC_BRANCH="master"
UPSYNC_CHECKOUT="6b75f7a6801a0790c553750093733ff3bc7b428e"
# stream upsync
STREAM_UPSYNC_GIT="https://github.com/xiaokai-wang/nginx-stream-upsync-module.git"
STREAM_UPSYNC_BRANCH="master"
STREAM_UPSYNC_CHECKOUT="1e08f352a76737555f5d8e209940bc6ec4c98a28"
# server traffic status
STS_GIT="https://github.com/vozlt/nginx-module-sts.git"
STS_BRANCH="master"
STS_CHECKOUT="06ea32162654401b08e5e486155b9a2981623298"
# stream server traffic status
STREAM_STS_GIT="https://github.com/vozlt/nginx-module-stream-sts.git"
STREAM_STS_BRANCH="master"
STREAM_STS_CHECKOUT="54494ccd33ddfeb1b458409caf1261d16ba31c27"
# virtual host traffic status
VTS_GIT="https://github.com/vozlt/nginx-module-vts.git"
VTS_BRANCH="master"
VTS_CHECKOUT="46d85558e344dfe2b078ce757fd36c69a1ec2dd3"
# sysguard
SYSGUARD_GIT="https://github.com/vozlt/nginx-module-sysguard.git"
SYSGUARD_BRANCH="master"
SYSGUARD_CHECKOUT="e512897f5aba4f79ccaeeebb51138f1704a58608"
# test cookie
TEST_COOKIE_GIT="https://github.com/kyprizel/testcookie-nginx-module.git"
TEST_COOKIE_BRANCH="master"
TEST_COOKIE_CHECKOUT="3e0a32f611dc98406f0ae8b1fce12673dbc62eaf"
# upload progress
UPLOAD_PROGRESS_GIT="https://github.com/masterzen/nginx-upload-progress-module.git"
UPLOAD_PROGRESS_BRANCH="master"
UPLOAD_PROGRESS_CHECKOUT="afb2d31d1277c50bd6215c470ba94b843349e250"
# vod
VOD_GIT="https://github.com/kaltura/nginx-vod-module.git"
VOD_BRANCH="master"
VOD_CHECKOUT="5e45bd2939e1e5edfdb3e05366b1323007895260"
# zip
ZIP_GIT="https://github.com/evanmiller/mod_zip.git"
ZIP_BRANCH="master"
ZIP_CHECKOUT="255cf540ac53865df93e022bb8c20f1a1e9a54da"
#######################################################
###           END OF MODULES GIT DETAILS            ###
#######################################################

#######################################################
###              NGINX BUILD DETAILS                ###
#######################################################
# BUILD configuration
NG_CFLAGS="CFLAGS=\"-O3 -Wno-deprecated-declarations\""
NG_LDFLAGS="LDFLAGS=\"-Wl,-rpath,$PHP_LIB\""
# options
NGINX_OPTIONS="--prefix=/etc/nginx"
NGINX_OPTIONS="$NGINX_OPTIONS --sbin-path=/usr/sbin/nginx"
NGINX_OPTIONS="$NGINX_OPTIONS --modules-path=/usr/lib/nginx/modules"
NGINX_OPTIONS="$NGINX_OPTIONS --conf-path=/etc/nginx/nginx.conf"
NGINX_OPTIONS="$NGINX_OPTIONS --error-log-path=/var/log/nginx/error.log"
NGINX_OPTIONS="$NGINX_OPTIONS --http-log-path=/var/log/nginx/access.log"
NGINX_OPTIONS="$NGINX_OPTIONS --pid-path=/var/run/nginx.pid"
NGINX_OPTIONS="$NGINX_OPTIONS --http-client-body-temp-path=/var/cache/nginx/client_temp"
NGINX_OPTIONS="$NGINX_OPTIONS --http-proxy-temp-path=/var/cache/nginx/proxy_temp"
NGINX_OPTIONS="$NGINX_OPTIONS --http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp"
NGINX_OPTIONS="$NGINX_OPTIONS --http-uwsgi-temp-path=/var/cache/nginx/uwsgi_temp"
NGINX_OPTIONS="$NGINX_OPTIONS --http-scgi-temp-path=/var/cache/nginx/scgi_temp"
NGINX_OPTIONS="$NGINX_OPTIONS --user=nginx"
NGINX_OPTIONS="$NGINX_OPTIONS --group=nginx"
# core
NGINX_MODULES_CORE="--with-compat"
NGINX_MODULES_CORE="$NGINX_MODULES_CORE --with-file-aio"
NGINX_MODULES_CORE="$NGINX_MODULES_CORE --with-threads"
NGINX_MODULES_CORE="$NGINX_MODULES_CORE --with-http_addition_module"
NGINX_MODULES_CORE="$NGINX_MODULES_CORE --with-http_auth_request_module"
NGINX_MODULES_CORE="$NGINX_MODULES_CORE --with-http_dav_module"
NGINX_MODULES_CORE="$NGINX_MODULES_CORE --with-http_flv_module"
NGINX_MODULES_CORE="$NGINX_MODULES_CORE --with-http_gunzip_module"
NGINX_MODULES_CORE="$NGINX_MODULES_CORE --with-http_gzip_static_module"
NGINX_MODULES_CORE="$NGINX_MODULES_CORE --with-http_mp4_module"
NGINX_MODULES_CORE="$NGINX_MODULES_CORE --with-http_random_index_module"
NGINX_MODULES_CORE="$NGINX_MODULES_CORE --with-http_realip_module"
NGINX_MODULES_CORE="$NGINX_MODULES_CORE --with-http_secure_link_module"
NGINX_MODULES_CORE="$NGINX_MODULES_CORE --with-http_slice_module"
NGINX_MODULES_CORE="$NGINX_MODULES_CORE --with-http_ssl_module"
NGINX_MODULES_CORE="$NGINX_MODULES_CORE --with-http_stub_status_module"
NGINX_MODULES_CORE="$NGINX_MODULES_CORE --with-http_sub_module"
NGINX_MODULES_CORE="$NGINX_MODULES_CORE --with-http_v2_module"
NGINX_MODULES_CORE="$NGINX_MODULES_CORE --with-mail_ssl_module"
NGINX_MODULES_CORE="$NGINX_MODULES_CORE --with-pcre-jit"
NGINX_MODULES_CORE="$NGINX_MODULES_CORE --with-stream"
NGINX_MODULES_CORE="$NGINX_MODULES_CORE --with-stream_realip_module"
NGINX_MODULES_CORE="$NGINX_MODULES_CORE --with-stream_ssl_module"
NGINX_MODULES_CORE="$NGINX_MODULES_CORE --with-stream_ssl_preread_module"
# core dynamics
NGINX_MODULES_CORE="$NGINX_MODULES_CORE --with-http_geoip_module=dynamic"
NGINX_MODULES_CORE="$NGINX_MODULES_CORE --with-http_image_filter_module=dynamic"
NGINX_MODULES_CORE="$NGINX_MODULES_CORE --with-http_perl_module=dynamic"
NGINX_MODULES_CORE="$NGINX_MODULES_CORE --with-http_xslt_module=dynamic"
NGINX_MODULES_CORE="$NGINX_MODULES_CORE --with-mail=dynamic"
NGINX_MODULES_CORE="$NGINX_MODULES_CORE --with-stream_geoip_module=dynamic"
# Thirds
NGINX_MODULES=""
#######################################################
###           END OF NGINX BUILD DETAILS            ###
#######################################################


_get_dependencies() {
    apt clean && apt update
    apt install build-essential cmake libbison-dev libsass-dev libldap2-dev libzmq3-dev libbsd-dev libhiredis-dev libmaxminddb-dev libpam0g-dev libsodium-dev libphp-embed libargon2-dev systemtap-sdt-dev php-dev mercurial libperl-dev libgd-dev libxml2-dev libxslt-dev build-essential git curl gnupg2 dpkg-dev dpkg-sig devscripts -y
    curl -O https://nginx.org/keys/nginx_signing.key && apt-key add ./nginx_signing.key
    echo "deb http://nginx.org/packages/debian/ buster nginx" \
        > /etc/apt/sources.list.d/nginx-stable.list
    echo "deb-src http://nginx.org/packages/debian/ buster nginx" \
        >> /etc/apt/sources.list.d/nginx-stable.list
    # checkinstall is in backports
    echo "deb http://deb.debian.org/debian buster-backports main" \
        > /etc/apt/sources.list.d/buster-backports.list
    apt clean && apt update
    apt -t buster-backports install checkinstall
}

_get_source_ready() {
    mkdir -p "$NG_WORKING_DIR"
    cd "$NG_WORKING_DIR" && apt source nginx
}

_get_modules_ready() {
    mkdir -p "$NG_MOD_PATH"
    # OpenSSL
    if [[ "$QUICHE" = 'y' ]]; then
        cd "$NG_MOD_PATH"
        git clone --branch "$QUICHE_BRANCH" --recursive "$QUICHE_GIT"
        cd quiche
        git checkout "$QUICHE_CHECKOUT"
        cd "$NG_SRC_PATH"
        patch -p01 < "$NG_MOD_PATH"/quiche/extras/nginx/nginx-1.16.patch
    fi
    if [[ "$OPENSSL" = 'y' ]]; then
        cd "$NG_MOD_PATH"
        git clone --branch "$OPENSSL_BRANCH" "$OPENSSL_GIT"
        cd openssl
        git checkout "$OPENSSL_CHECKOUT"
        ./config
    fi
    # PageSpeed
    if [[ "$PAGESPEED" = 'y' ]]; then
        cd "$NG_MOD_PATH"
        if [[ "$INSTALL_APT_LIBS" = 'y' ]]; then
            apt install zlib1g-dev libpcre3-dev unzip uuid-dev -y
        fi
        git clone --branch "$PAGESPEED_BRANCH" "$PAGESPEED_GIT"
        cd incubator-pagespeed-ngx
        git checkout "$PAGESPEED_CHECKOUT"
        cd scripts
        chmod +x build_ngx_pagespeed.sh
        ./build_ngx_pagespeed.sh --ngx-pagespeed-version latest-stable -b "$NG_MOD_PATH"
    fi
    # NAXSI
    if [[ "$NAXSI" = 'y' ]]; then
        cd "$NG_MOD_PATH"
        git clone --branch "$NAXSI_BRANCH" "$NAXSI_GIT"
        cd naxsi
        git checkout "$NAXSI_CHECKOUT"
        mv naxsi_config config
        cd "$NG_MOD_PATH"
        cd naxsi
        git clone --branch "$NAXSI_RULES_BRANCH" "$NAXSI_RULES_GIT" rules
        cd rules
        git checkout "$NAXSI_RULES_CHECKOUT"
    fi
    # modsecurity
    if [[ "$MODSECURITY" = 'y' ]]; then
        if [[ "$INSTALL_APT_LIBS" = 'y' ]]; then
            apt install -y apt-utils autoconf automake build-essential git libcurl4-openssl-dev libgeoip-dev liblmdb-dev libpcre++-dev libtool libxml2-dev libyajl-dev pkgconf wget zlib1g-dev
        fi
        if [[ "$INSTALL_SRC_LIBS" = 'y' ]]; then
            cd "$NG_MOD_PATH"
            git clone --branch "$MODSEC_LIB_BRANCH" "$MODSEC_LIB_GIT"
            cd ModSecurity
            git checkout "$MODSEC_LIB_CHECKOUT"
            git submodule init
            git submodule update
            ./build.sh
            ./configure
            make
            make uninstall
            make install
        fi
        if [[ "$MAKE_PKG_SRC_LIBS" = 'y' ]]; then
            checkinstall --install=no --nodoc
        fi
        cd "$NG_MOD_PATH"
        git clone --branch "$MODSEC_NGINX_BRANCH" "$MODSEC_NGINX_GIT"
        cd ModSecurity-nginx
        git checkout "$MODSEC_NGINX_CHECKOUT"
        cd "$NG_MOD_PATH"
        git clone --branch "$MODSEC_CRS_BRANCH" "$MODSEC_CRS_GIT" crs
        cd crs
        git checkout "$MODSEC_CRS_CHECKOUT"
    fi
    # brotli
    if [[ "$BROTLI" = 'y' ]]; then
        cd "$NG_MOD_PATH"
        git clone --branch "$BROTLI_BRANCH" "$BROTLI_GIT"
        cd ngx_brotli
        git checkout "$BROTLI_CHECKOUT"
        git submodule init
        git submodule update
    fi
    # devkit
    if [[ "$DEVKIT" = 'y' ]]; then
        cd "$NG_MOD_PATH"
        git clone --branch "$DEVKIT_BRANCH" "$DEVKIT_GIT"
        cd ngx_devel_kit
        git checkout "$DEVKIT_CHECKOUT"
    fi
    # akamai g2o
    if [[ "$AKAMAI_G2O" = 'y' ]]; then
        cd "$NG_MOD_PATH"
        git clone --branch "$AKAMAI_G2O_BRANCH" "$AKAMAI_G2O_GIT"
        cd nginx_mod_akamai_g2o
        git checkout "$AKAMAI_G2O_CHECKOUT"
    fi
    # njs
    if [[ "$NJS" = 'y' ]]; then
        cd "$NG_MOD_PATH"
        git clone --branch "$NJS_BRANCH" "$NJS_GIT"
        cd njs
        git checkout "$NJS_CHECKOUT"
    fi
    # xss
    if [[ "$XSS" = 'y' ]]; then
        cd "$NG_MOD_PATH"
        git clone --branch "$XSS_BRANCH" "$XSS_GIT"
        cd xss-nginx-module
        git checkout "$XSS_CHECKOUT"
    fi
    # php7
    if [[ "$PHP7" = 'y' ]]; then
        cd "$NG_MOD_PATH"
        git clone --branch "$PHP7_BRANCH" "$PHP7_GIT"
        cd ngx_php7
        git checkout "$PHP7_CHECKOUT"
    fi
    # auth pam
    if [[ "$AUTH_PAM" = 'y' ]]; then
        cd "$NG_MOD_PATH"
        git clone --branch "$AUTH_PAM_BRANCH" "$AUTH_PAM_GIT"
        cd ngx_http_auth_pam_module
        git checkout "$AUTH_PAM_CHECKOUT"
    fi
    # auth digest
    if [[ "$AUTH_DIGEST" = 'y' ]]; then
        cd "$NG_MOD_PATH"
        git clone --branch "$AUTH_DIGEST_BRANCH" "$AUTH_DIGEST_GIT"
        cd nginx-http-auth-digest 
        git checkout "$AUTH_DIGEST_CHECKOUT"
    fi
    # cache purge
    if [[ "$CACHE_PURGE" = 'y' ]]; then
        cd "$NG_MOD_PATH"
        git clone --branch "$CACHE_PURGE_BRANCH" "$CACHE_PURGE_GIT"
        cd ngx_cache_purge
        git checkout "$CACHE_PURGE_CHECKOUT"
        # fix config for dynamic module
        wget https://eu.sta.deb.rep.apa.sh:8888/cache_purge/config -O config
    fi
    # cookie flag
    if [[ "$COOKIE_FLAG" = 'y' ]]; then
        cd "$NG_MOD_PATH"
        git clone --branch "$COOKIE_FLAG_BRANCH" "$COOKIE_FLAG_GIT"
        cd nginx_cookie_flag_module
        git checkout "$COOKIE_FLAG_CHECKOUT"
    fi
    # echo sleep time exec ..
    if [[ "$ECHO" = 'y' ]]; then
        cd "$NG_MOD_PATH"
        git clone --branch "$ECHO_BRANCH" "$ECHO_GIT"
        cd echo-nginx-module
        git checkout "$ECHO_CHECKOUT"
    fi
    # execute
    if [[ "$EXECUTE" = 'y' ]]; then
        cd "$NG_MOD_PATH"
        git clone --branch "$EXECUTE_BRANCH" "$EXECUTE_GIT"
        cd NginxExecute
        git checkout "$EXECUTE_CHECKOUT"
    fi
    # elastic
    if [[ "$ELASTIC" = 'y' ]]; then
        cd "$NG_MOD_PATH"
        git clone --branch "$ELASTIC_BRANCH" "$ELASTIC_GIT"
        cd nginx-elastic-client
        git checkout "$ELASTIC_CHECKOUT"
    fi
    # encrypted session
    if [[ "$ENCRYPTED_SESSION" = 'y' ]]; then
        cd "$NG_MOD_PATH"
        git clone --branch "$ENCRYPTED_SESSION_BRANCH" "$ENCRYPTED_SESSION_GIT"
        cd encrypted-session-nginx-module
        git checkout "$ENCRYPTED_SESSION_CHECKOUT"
    fi
    # dynamic limit request
    if [[ "$DYN_LIMIT_REQ" = 'y' ]]; then
        cd "$NG_MOD_PATH"
        git clone --branch "$DYN_LIMIT_REQ_BRANCH" "$DYN_LIMIT_REQ_GIT"
        cd ngx_dynamic_limit_req_module
        git checkout "$DYN_LIMIT_REQ_CHECKOUT"
    fi
    # form input
    if [[ "$FORM_INPUT" = 'y' ]]; then
        cd "$NG_MOD_PATH"
        git clone --branch "$FORM_INPUT_BRANCH" "$FORM_INPUT_GIT"
        cd form-input-nginx-module
        git checkout "$FORM_INPUT_CHECKOUT"
    fi
    # geoip2
    if [[ "$GEOIP2" = 'y' ]]; then
        cd "$NG_MOD_PATH"
        git clone --branch "$GEOIP2_BRANCH" "$GEOIP2_GIT"
        cd ngx_http_geoip2_module
        git checkout "$GEOIP2_CHECKOUT"
    fi
    # traffic accounting
    if [[ "$TRAFFIC_ACC" = 'y' ]]; then
        cd "$NG_MOD_PATH"
        git clone --branch "$TRAFFIC_ACC_BRANCH" "$TRAFFIC_ACC_GIT"
        cd traffic-accounting-nginx-module
        git checkout "$TRAFFIC_ACC_CHECKOUT"
    fi
    # headers more
    if [[ "$HEADERS_MORE" = 'y' ]]; then
        cd "$NG_MOD_PATH"
        git clone --branch "$HEADERS_MORE_BRANCH" "$HEADERS_MORE_GIT"
        cd headers-more-nginx-module
        git checkout "$HEADERS_MORE_CHECKOUT"
    fi
    # nginx upstream check
    if [[ "$UPSTREAM_CHECK" = 'y' ]]; then
        cd "$NG_MOD_PATH"
        git clone --branch "$UPSTREAM_CHECK_BRANCH" "$UPSTREAM_CHECK_GIT"
        cd nginx_upstream_check_module
        git checkout "$UPSTREAM_CHECK_CHECKOUT"
        # patch here
        cd "$NG_SRC_PATH"
        patch -p1 < "$NG_MOD_PATH"/nginx_upstream_check_module/check_1.16.1+.patch
    fi
    # ipscrub
    if [[ "$IPSCRUB" = 'y' ]]; then
        cd "$NG_MOD_PATH"
        git clone --branch "$IPSCRUB_BRANCH" "$IPSCRUB_GIT"
        cd ipscrub
        git checkout "$IPSCRUB_CHECKOUT"
    fi
    # log ZeroMQ
    if [[ "$LOG_ZEROMQ" = 'y' ]]; then
        cd "$NG_MOD_PATH"
        git clone --branch "$LOG_ZEROMQ_BRANCH" "$LOG_ZEROMQ_GIT"
        cd nginx-log-zmq
        git checkout "$LOG_ZEROMQ_CHECKOUT"
    fi
    # ldap
    if [[ "$LDAP" = 'y' ]]; then
        cd "$NG_MOD_PATH"
        git clone --branch "$LDAP_BRANCH" "$LDAP_GIT"
        cd nginx-auth-ldap
        git checkout "$LDAP_CHECKOUT"
    fi
    # modjpeg
    if [[ "$MODJPEG" = 'y' ]]; then
        if [[ "$INSTALL_SRC_LIBS" = 'y' ]]; then
            cd "$NG_MOD_PATH"
            git clone --branch "$MODJPEG_LIB_BRANCH" "$MODJPEG_LIB_GIT"
            cd libmodjpeg
            git checkout "$MODJPEG_LIB_CHECKOUT"
            cmake .
            make
            make uninstall
            make install
        fi
        if [[ "$MAKE_PKG_SRC_LIBS" = 'y' ]]; then
            checkinstall --install=no --nodoc
        fi
        cd "$NG_MOD_PATH"
        git clone --branch "$MODJPEG_BRANCH" "$MODJPEG_GIT"
        cd modjpeg-nginx
        git checkout "$MODJPEG_CHECKOUT"
    fi
    # memc
    if [[ "$MEMC" = 'y' ]]; then
        cd "$NG_MOD_PATH"
        git clone --branch "$MEMC_BRANCH" "$MEMC_GIT"
        cd memc-nginx-module
        git checkout "$MEMC_CHECKOUT"
    fi
    # nchan
    if [[ "$NCHAN" = 'y' ]]; then
        cd "$NG_MOD_PATH"
        git clone --branch "$NCHAN_BRANCH" "$NCHAN_GIT"
        cd nchan
        git checkout "$NCHAN_CHECKOUT"
    fi
    # link function
    if [[ "$LINK_FUNCTION" = 'y' ]]; then
        cd "$NG_MOD_PATH"
        git clone --branch "$LINK_FUNCTION_BRANCH" "$LINK_FUNCTION_GIT"
        cd nginx-link-function
        git checkout "$LINK_FUNCTION_CHECKOUT"
        install -m 644 "$NG_MOD_PATH"/nginx-link-function/src/ngx_link_func_module.h /usr/local/include/
    fi
    # replace filter
    if [[ "$REPLACE_FILTER" = 'y' ]]; then
        if [[ "$INSTALL_SRC_LIBS" = 'y' ]]; then
            cd "$NG_MOD_PATH"
            git clone --branch "$REPLACE_FILTER_SREGEX_BRANCH" "$REPLACE_FILTER_SREGEX_GIT"
            cd sregex
            git checkout "$REPLACE_FILTER_SREGEX_CHECKOUT"
            make
            make uninstall
            make install
        fi
        if [[ "$MAKE_PKG_SRC_LIBS" = 'y' ]]; then
            checkinstall --install=no --nodoc
        fi
        cd "$NG_MOD_PATH"
        git clone --branch "$REPLACE_FILTER_BRANCH" "$REPLACE_FILTER_GIT"
        cd replace-filter-nginx-module
        git checkout "$REPLACE_FILTER_CHECKOUT"
    fi
    # redis2
    if [[ "$REDIS2" = 'y' ]]; then
        cd "$NG_MOD_PATH"
        git clone --branch "$REDIS2_BRANCH" "$REDIS2_GIT"
        cd redis2-nginx-module
        git checkout "$REDIS2_CHECKOUT"
    fi
    # rdns
    if [[ "$RDNS" = 'y' ]]; then
        cd "$NG_MOD_PATH"
        git clone --branch "$RDNS_BRANCH" "$RDNS_GIT"
        cd nginx-http-rdns
        git checkout "$RDNS_CHECKOUT"
    fi
    # push stream
    if [[ "$RDNS" = 'y' ]]; then
        cd "$NG_MOD_PATH"
        git clone --branch "$PUSH_STREAM_BRANCH" "$PUSH_STREAM_GIT"
        cd nginx-push-stream-module
        git checkout "$PUSH_STREAM_CHECKOUT"
    fi
    # rtmp
    if [[ "$RTMP" = 'y' ]]; then
        cd "$NG_MOD_PATH"
        git clone --branch "$RTMP_BRANCH" "$RTMP_GIT"
        cd nginx-rtmp-module
        git checkout "$RTMP_CHECKOUT"
    fi
    # rtmp proxy
    if [[ "$RTMPT_PROXY" = 'y' ]]; then
        cd "$NG_MOD_PATH"
        git clone --branch "$RTMPT_PROXY_BRANCH" "$RTMPT_PROXY_GIT"
        cd nginx-rtmpt-proxy-module
        git checkout "$RTMPT_PROXY_CHECKOUT"
    fi
    # security headers
    if [[ "$SEC_HEADERS" = 'y' ]]; then
        cd "$NG_MOD_PATH"
        git clone --branch "$SEC_HEADERS_BRANCH" "$SEC_HEADERS_GIT"
        cd ngx_security_headers
        git checkout "$SEC_HEADERS_CHECKOUT"
    fi
    # sass
    if [[ "$SASS" = 'y' ]]; then
        cd "$NG_MOD_PATH"
        git clone --branch "$SASS_BRANCH" "$SASS_GIT"
        cd sass-nginx-module
        git checkout "$SASS_CHECKOUT"
    fi
    # sorted querystring
    if [[ "$SORTED_QUERYSTRING" = 'y' ]]; then
        cd "$NG_MOD_PATH"
        git clone --branch "$SORTED_QUERYSTRING_BRANCH" "$SORTED_QUERYSTRING_GIT"
        cd nginx-sorted-querystring-module
        git checkout "$SORTED_QUERYSTRING_CHECKOUT"
    fi
    # srcache
    if [[ "$SRCACHE" = 'y' ]]; then
        cd "$NG_MOD_PATH"
        git clone --branch "$SRCACHE_BRANCH" "$SRCACHE_GIT"
        cd srcache-nginx-module
        git checkout "$SRCACHE_CHECKOUT"
    fi
    # upsync
    if [[ "$UPSYNC" = 'y' ]]; then
        cd "$NG_MOD_PATH"
        git clone --branch "$UPSYNC_BRANCH" "$UPSYNC_GIT"
        cd nginx-upsync-module
        git checkout "$UPSYNC_CHECKOUT"
    fi
    # stream upsync
    if [[ "$STREAM_UPSYNC" = 'y' ]]; then
        cd "$NG_MOD_PATH"
        git clone --branch "$STREAM_UPSYNC_BRANCH" "$STREAM_UPSYNC_GIT"
        cd nginx-stream-upsync-module
        git checkout "$STREAM_UPSYNC_CHECKOUT"
    fi
    # server traffic status
    if [[ "$STS" = 'y' ]]; then
        cd "$NG_MOD_PATH"
        git clone --branch "$STS_BRANCH" "$STS_GIT"
        cd nginx-module-sts
        git checkout "$STS_CHECKOUT"
    fi
    # stream server traffic status
    if [[ "$STREAM_STS" = 'y' ]]; then
        cd "$NG_MOD_PATH"
        git clone --branch "$STREAM_STS_BRANCH" "$STREAM_STS_GIT"
        cd nginx-module-stream-sts
        git checkout "$STREAM_STS_CHECKOUT"
    fi
    # virtual host traffic status
    if [[ "$VTS" = 'y' ]]; then
        cd "$NG_MOD_PATH"
        git clone --branch "$VTS_BRANCH" "$VTS_GIT"
        cd nginx-module-vts
        git checkout "$VTS_CHECKOUT"
    fi
    # virtual host traffic status
    if [[ "$SYSGUARD" = 'y' ]]; then
        cd "$NG_MOD_PATH"
        git clone --branch "$SYSGUARD_BRANCH" "$SYSGUARD_GIT"
        cd nginx-module-sysguard
        git checkout "$SYSGUARD_CHECKOUT"
    fi
    # test cookie
    if [[ "$TEST_COOKIE" = 'y' ]]; then
        cd "$NG_MOD_PATH"
        git clone --branch "$TEST_COOKIE_BRANCH" "$TEST_COOKIE_GIT"
        cd testcookie-nginx-module
        git checkout "$TEST_COOKIE_CHECKOUT"
    fi
    # upload progress
    if [[ "$UPLOAD_PROGRESS" = 'y' ]]; then
        cd "$NG_MOD_PATH"
        git clone --branch "$UPLOAD_PROGRESS_BRANCH" "$UPLOAD_PROGRESS_GIT"
        cd nginx-upload-progress-module
        git checkout "$UPLOAD_PROGRESS_CHECKOUT"
    fi
    # vod
    if [[ "$VOD" = 'y' ]]; then
        cd "$NG_MOD_PATH"
        git clone --branch "$VOD_BRANCH" "$VOD_GIT"
        cd nginx-vod-module
        git checkout "$VOD_CHECKOUT"
    fi
    # zip
    if [[ "$ZIP" = 'y' ]]; then
        cd "$NG_MOD_PATH"
        git clone --branch "$ZIP_BRANCH" "$ZIP_GIT"
        cd nginx-vod-module
        git checkout "$ZIP_CHECKOUT"
    fi
}

_build_install_nginx() {
    if [[ "$INSTALL_APT_LIBS" = 'y' ]]; then
        apt install debhelper dh-systemd quilt lsb-release libssl-dev -y
    fi
    cd "$NG_SRC_PATH"
    if [[ "$MAKE_NEW_FORK" = 'y' ]]; then
        cp debian/rules debian-rules-back
        cp debian/nginx.install nginx-install-back
    fi
    if [[ "$REWRITE_DEB_RULES" = 'y' ]]; then
        cp debian-rules-back debian/rules
        cp nginx-install-back debian/nginx.install
        sed -i "s|post-build:|post-build:\n\\tstrip --strip-unneeded \$(BUILDDIR_nginx)/objs/*.so|g" debian/rules
        sed -i "s|post-build:|post-build:\n\\tstrip --strip-unneeded \$(BUILDDIR_nginx)/objs/nginx|g" debian/rules
    fi

    if [[ "$QUICHE" = 'y' ]]; then
        NGINX_MODULES="$NGINX_MODULES --with-http_v3_module"
        NGINX_MODULES="$NGINX_MODULES --with-openssl=../../$MOD_DIR_NAME/quiche/deps/boringssl"
        NGINX_MODULES="$NGINX_MODULES --with-quiche=../../$MOD_DIR_NAME/quiche"
    fi
    if [[ "$OPENSSL" = 'y' ]]; then
        NGINX_MODULES="$NGINX_MODULES --with-openssl=../../$MOD_DIR_NAME/openssl"
    fi
    if [[ "$PAGESPEED" = 'y' ]]; then
        NGINX_MODULES="$NGINX_MODULES --add-dynamic-module=../../$MOD_DIR_NAME/incubator-pagespeed-ngx-latest-stable"
    fi
    if [[ "$NAXSI" = 'y' ]]; then
        NGINX_MODULES="$NGINX_MODULES --add-dynamic-module=../../$MOD_DIR_NAME/naxsi/naxsi_src"
    fi
    if [[ "$MODSECURITY" = 'y' ]]; then
        # modsecurity fix build
        if [[ "$REWRITE_DEB_RULES" = 'y' ]]; then
            sed -i "s|dh_shlibdeps -a|dh_shlibdeps -a --dpkg-shlibdeps-params=--ignore-missing-info|g" debian/rules
        fi
        NGINX_MODULES="$NGINX_MODULES --add-dynamic-module=../../$MOD_DIR_NAME/ModSecurity-nginx"
    fi
    if [[ "$BROTLI" = 'y' ]]; then
        NGINX_MODULES="$NGINX_MODULES --add-dynamic-module=../../$MOD_DIR_NAME/ngx_brotli"
    fi
    if [[ "$DEVKIT" = 'y' ]]; then
        NGINX_MODULES="$NGINX_MODULES --add-dynamic-module=../../$MOD_DIR_NAME/ngx_devel_kit"
    fi
    if [[ "$AKAMAI_G2O" = 'y' ]]; then
        NGINX_MODULES="$NGINX_MODULES --add-dynamic-module=../../$MOD_DIR_NAME/nginx_mod_akamai_g2o"
    fi
    if [[ "$NJS" = 'y' ]]; then
        NGINX_MODULES="$NGINX_MODULES --add-dynamic-module=../../$MOD_DIR_NAME/njs/nginx"
    fi
    if [[ "$XSS" = 'y' ]]; then
        NGINX_MODULES="$NGINX_MODULES --add-dynamic-module=../../$MOD_DIR_NAME/xss-nginx-module"
    fi
    if [[ "$PHP7" = 'y' ]]; then
        NGINX_MODULES="$NGINX_MODULES --add-dynamic-module=../../$MOD_DIR_NAME/ngx_php7"
    fi
    if [[ "$AUTH_PAM" = 'y' ]]; then
        NGINX_MODULES="$NGINX_MODULES --add-dynamic-module=../../$MOD_DIR_NAME/ngx_http_auth_pam_module"
    fi
    if [[ "$AUTH_DIGEST" = 'y' ]]; then
        NGINX_MODULES="$NGINX_MODULES --add-dynamic-module=../../$MOD_DIR_NAME/nginx-http-auth-digest"
    fi
    if [[ "$CACHE_PURGE" = 'y' ]]; then
        NGINX_MODULES="$NGINX_MODULES --add-dynamic-module=../../$MOD_DIR_NAME/ngx_cache_purge"
    fi
    if [[ "$COOKIE_FLAG" = 'y' ]]; then
        NGINX_MODULES="$NGINX_MODULES --add-dynamic-module=../../$MOD_DIR_NAME/nginx_cookie_flag_module"
    fi
    if [[ "$ECHO" = 'y' ]]; then
        NGINX_MODULES="$NGINX_MODULES --add-dynamic-module=../../$MOD_DIR_NAME/echo-nginx-module"
    fi
    if [[ "$EXECUTE" = 'y' ]]; then
        NGINX_MODULES="$NGINX_MODULES --add-dynamic-module=../../$MOD_DIR_NAME/NginxExecute"
    fi
    if [[ "$ELASTIC" = 'y' ]]; then
        NGINX_MODULES="$NGINX_MODULES --add-dynamic-module=../../$MOD_DIR_NAME/nginx-elastic-client"
    fi
    if [[ "$ENCRYPTED_SESSION" = 'y' ]]; then
        NGINX_MODULES="$NGINX_MODULES --add-dynamic-module=../../$MOD_DIR_NAME/encrypted-session-nginx-module"
    fi
    if [[ "$DYN_LIMIT_REQ" = 'y' ]]; then
        NGINX_MODULES="$NGINX_MODULES --add-dynamic-module=../../$MOD_DIR_NAME/ngx_dynamic_limit_req_module"
    fi
    if [[ "$FORM_INPUT" = 'y' ]]; then
        NGINX_MODULES="$NGINX_MODULES --add-dynamic-module=../../$MOD_DIR_NAME/form-input-nginx-module"
    fi
    if [[ "$GEOIP2" = 'y' ]]; then
        NGINX_MODULES="$NGINX_MODULES --add-dynamic-module=../../$MOD_DIR_NAME/ngx_http_geoip2_module"
    fi
    if [[ "$TRAFFIC_ACC" = 'y' ]]; then
        NGINX_MODULES="$NGINX_MODULES --add-dynamic-module=../../$MOD_DIR_NAME/traffic-accounting-nginx-module"
    fi
    if [[ "$HEADERS_MORE" = 'y' ]]; then
        NGINX_MODULES="$NGINX_MODULES --add-dynamic-module=../../$MOD_DIR_NAME/headers-more-nginx-module"
    fi
    if [[ "$UPSTREAM_CHECK" = 'y' ]]; then
        NGINX_MODULES="$NGINX_MODULES --add-dynamic-module=../../$MOD_DIR_NAME/nginx_upstream_check_module"
    fi
    if [[ "$IPSCRUB" = 'y' ]]; then
        NGINX_MODULES="$NGINX_MODULES --add-dynamic-module=../../$MOD_DIR_NAME/ipscrub/ipscrub"
    fi
    if [[ "$LOG_ZEROMQ" = 'y' ]]; then
        NGINX_MODULES="$NGINX_MODULES --add-dynamic-module=../../$MOD_DIR_NAME/nginx-log-zmq"
    fi
    if [[ "$LDAP" = 'y' ]]; then
        NGINX_MODULES="$NGINX_MODULES --add-dynamic-module=../../$MOD_DIR_NAME/nginx-auth-ldap"
    fi
    if [[ "$MODJPEG" = 'y' ]]; then
        NGINX_MODULES="$NGINX_MODULES --add-dynamic-module=../../$MOD_DIR_NAME/modjpeg-nginx"
    fi
    if [[ "$MEMC" = 'y' ]]; then
        NGINX_MODULES="$NGINX_MODULES --add-dynamic-module=../../$MOD_DIR_NAME/memc-nginx-module"
    fi
    if [[ "$NCHAN" = 'y' ]]; then
        NGINX_MODULES="$NGINX_MODULES --add-dynamic-module=../../$MOD_DIR_NAME/nchan"
    fi
    if [[ "$LINK_FUNCTION" = 'y' ]]; then
        NGINX_MODULES="$NGINX_MODULES --add-dynamic-module=../../$MOD_DIR_NAME/nginx-link-function"
    fi
    if [[ "$REPLACE_FILTER" = 'y' ]]; then
        NGINX_MODULES="$NGINX_MODULES --add-dynamic-module=../../$MOD_DIR_NAME/replace-filter-nginx-module"
    fi
    if [[ "$REDIS2" = 'y' ]]; then
        NGINX_MODULES="$NGINX_MODULES --add-dynamic-module=../../$MOD_DIR_NAME/redis2-nginx-module"
    fi
    if [[ "$RDNS" = 'y' ]]; then
        NGINX_MODULES="$NGINX_MODULES --add-dynamic-module=../../$MOD_DIR_NAME/nginx-http-rdns"
    fi
    if [[ "$PUSH_STREAM" = 'y' ]]; then
        NGINX_MODULES="$NGINX_MODULES --add-dynamic-module=../../$MOD_DIR_NAME/nginx-push-stream-module"
    fi
    if [[ "$RTMP" = 'y' ]]; then
        NGINX_MODULES="$NGINX_MODULES --add-dynamic-module=../../$MOD_DIR_NAME/nginx-rtmp-module"
    fi
    if [[ "$RTMPT_PROXY" = 'y' ]]; then
        NGINX_MODULES="$NGINX_MODULES --add-dynamic-module=../../$MOD_DIR_NAME/nginx-rtmpt-proxy-module"
    fi
    if [[ "$SEC_HEADERS" = 'y' ]]; then
        NGINX_MODULES="$NGINX_MODULES --add-dynamic-module=../../$MOD_DIR_NAME/ngx_security_headers"
    fi
    if [[ "$SASS" = 'y' ]]; then
        NGINX_MODULES="$NGINX_MODULES --add-dynamic-module=../../$MOD_DIR_NAME/sass-nginx-module"
    fi
    if [[ "$SORTED_QUERYSTRING" = 'y' ]]; then
        NGINX_MODULES="$NGINX_MODULES --add-dynamic-module=../../$MOD_DIR_NAME/nginx-sorted-querystring-module"
    fi
    if [[ "$SRCACHE" = 'y' ]]; then
        NGINX_MODULES="$NGINX_MODULES --add-dynamic-module=../../$MOD_DIR_NAME/srcache-nginx-module"
    fi
    if [[ "$UPSYNC" = 'y' ]]; then
        NGINX_MODULES="$NGINX_MODULES --add-dynamic-module=../../$MOD_DIR_NAME/nginx-upsync-module"
    fi
    if [[ "$STREAM_UPSYNC" = 'y' ]]; then
        NGINX_MODULES="$NGINX_MODULES --add-dynamic-module=../../$MOD_DIR_NAME/nginx-stream-upsync-module"
    fi
    if [[ "$STS" = 'y' ]]; then
        NGINX_MODULES="$NGINX_MODULES --add-dynamic-module=../../$MOD_DIR_NAME/nginx-module-sts"
    fi
    if [[ "$STREAM_STS" = 'y' ]]; then
        NGINX_MODULES="$NGINX_MODULES --add-dynamic-module=../../$MOD_DIR_NAME/nginx-module-stream-sts"
    fi
    if [[ "$VTS" = 'y' ]]; then
        NGINX_MODULES="$NGINX_MODULES --add-dynamic-module=../../$MOD_DIR_NAME/nginx-module-vts"
    fi
    if [[ "$SYSGUARD" = 'y' ]]; then
        NGINX_MODULES="$NGINX_MODULES --add-dynamic-module=../../$MOD_DIR_NAME/nginx-module-sysguard"
    fi
    if [[ "$TEST_COOKIE" = 'y' ]]; then
        NGINX_MODULES="$NGINX_MODULES --add-dynamic-module=../../$MOD_DIR_NAME/testcookie-nginx-module"
    fi
    if [[ "$UPLOAD_PROGRESS" = 'y' ]]; then
        NGINX_MODULES="$NGINX_MODULES --add-dynamic-module=../../$MOD_DIR_NAME/nginx-upload-progress-module"
    fi
    if [[ "$VOD" = 'y' ]]; then
        NGINX_MODULES="$NGINX_MODULES --add-dynamic-module=../../$MOD_DIR_NAME/nginx-vod-module"
    fi
    if [[ "$ZIP" = 'y' ]]; then
        NGINX_MODULES="$NGINX_MODULES --add-dynamic-module=../../$MOD_DIR_NAME/mod_zip"
    fi

    if [[ "$REWRITE_DEB_RULES" = 'y' ]]; then
        mkdir "$NG_APASH_CONFIG_PATH"
        # make module.conf
        cd debian/build-nginx/objs
        echo "$(ls -h *.so)" > "$NG_APASH_CONFIG_PATH"/modules.conf
        sed -i 's|^|#load_module modules/|' "$NG_APASH_CONFIG_PATH"/modules.conf
        sed -i 's|$|;|' "$NG_APASH_CONFIG_PATH"/modules.conf
        sed -i '1 i\#######################################################' "$NG_APASH_CONFIG_PATH"/modules.conf
        sed -i '1 i\###    this list is simply sorted alphabetically    ###' "$NG_APASH_CONFIG_PATH"/modules.conf
        sed -i '1 i\#######################################################' "$NG_APASH_CONFIG_PATH"/modules.conf
        sed -i '1 i\###          UNCOMMENT AND LOAD BY ORDER            ###' "$NG_APASH_CONFIG_PATH"/modules.conf
        sed -i '1 i\#######################################################' "$NG_APASH_CONFIG_PATH"/modules.conf
    fi

    cd "$NG_SRC_PATH"
    if [[ "$REWRITE_DEB_RULES" = 'y' ]]; then
        # copy all dynamics modules
        echo -e "debian/build-nginx/objs/*.so   usr/lib/nginx/modules" >> debian/nginx.install
        if [[ "$UPSTREAM_CHECK" = 'y' ]]; then
            echo -e "$MOD_DIR_NAME/nginx_upstream_check_module/doc   usr/lib/nginx/modules/upstream_check" >> debian/nginx.install
        fi
        # copy custom apash files !!! 
        echo -e "$MOD_DIR_NAME/$NG_APASH_CONFIG_DIR_NAME/*   etc/nginx" >> debian/nginx.install
        # naxsi stuff
        echo -e "$MOD_DIR_NAME/naxsi/nxapi   usr/lib/nginx/modules/naxsi" >> debian/nginx.install
        echo -e "$MOD_DIR_NAME/naxsi/config   usr/lib/nginx/modules/naxsi" >> debian/nginx.install
        echo -e "$MOD_DIR_NAME/naxsi/rules   usr/lib/nginx/modules/naxsi/config" >> debian/nginx.install
        # modsecurity stuff
        echo -e "$MOD_DIR_NAME/crs   usr/lib/nginx/modules/modsecurity" >> debian/nginx.install
        # traffic accounting monitoring
        echo -e "$MOD_DIR_NAME/traffic-accounting-nginx-module/samples   usr/lib/nginx/modules/trafficaccounting" >> debian/nginx.install
        # ldap example
        echo -e "$MOD_DIR_NAME/nginx-auth-ldap/example.conf   usr/lib/nginx/modules/ldap" >> debian/nginx.install
        # nchan
        echo -e "$MOD_DIR_NAME/nchan/dev   usr/lib/nginx/modules/nchan" >> debian/nginx.install
        # push stream
        echo -e "$MOD_DIR_NAME/nginx-push-stream-module/docs   usr/lib/nginx/modules/pushstream" >> debian/nginx.install
        echo -e "$MOD_DIR_NAME/nginx-push-stream-module/misc   usr/lib/nginx/modules/pushstream" >> debian/nginx.install
        # server traffic status
        echo -e "$MOD_DIR_NAME/nginx-module-sts/share   usr/lib/nginx/modules/sts" >> debian/nginx.install
        # virtual host traffic status
        echo -e "$MOD_DIR_NAME/nginx-module-vts/share   usr/lib/nginx/modules/vts" >> debian/nginx.install
        # test cookie
        echo -e "$MOD_DIR_NAME/testcookie-nginx-module/doc   usr/lib/nginx/modules/testcookie" >> debian/nginx.install
    fi
    if [[ "$REWRITE_DEB_RULES" = 'y' ]]; then
        # configure for default and debug
        sed -i "s|.*CFLAGS=\"\".*|\\t$NG_CFLAGS $NG_LDFLAGS \./configure $NGINX_OPTIONS $NGINX_MODULES_CORE $NGINX_MODULES --with-cc-opt=\"\$(CFLAGS)\" --with-ld-opt=\"\$(LDFLAGS)\"|g" debian/rules
        # add debug arg to second ./configure occurrence
        if [[ "$(sed 's|\.\/configure --with-debug|azertyuiop|g' debian/rules | grep -c azertyuiop)" = '0' ]]; then
            sed -i ': 1 ; N ; $!b1 ; s|\.\/configure|\.\/configure --with-debug|2 ' debian/rules 
        fi
    fi

    dch -i
    dpkg-buildpackage -rfakeroot -Tclean
    echo | dpkg-buildpackage -uc -b

}

# GET Dependencies
if [[ "$INSTALL_APT_LIBS" = 'y' ]]; then
    _get_dependencies
fi
# GET Nginx src
if [[ "$MAKE_NEW_FORK" = 'y' ]]; then
    _get_source_ready
fi
# GET Modules and cook it
if [[ "$NEED_MODULES_CLONE_AND_UPDATE" = 'y' ]]; then
    _get_modules_ready
fi
# BUILD INSTALL nginx
_build_install_nginx

