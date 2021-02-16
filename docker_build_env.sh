#!/bin/sh

if [ -z "$BUILD_ENV" -o ! -f "$BUILD_ENV" ]; then
	echo "Environment file '$BUILD_ENV' not found" 1>&2
	exit 1
fi

. $BUILD_ENV
docker build \
	--tag otto:latest \
	--build-arg NR_LICENSE_B="$NR_LICENSE" \
	--build-arg ROUTER_SSH_PUBKEY_B="$ROUTER_SSH_PUBKEY" \
	--build-arg ROUTER_SSH_PRIVKEY_B="$ROUTER_SSH_PRIVKEY" \
	--build-arg SLACK_WEBHOOK_B="$SLACK_WEBHOOK" \
	--build-arg ROUTER_HOSTNAME_B="$ROUTER_HOSTNAME" \
	--build-arg ROUTER_USERNAME_B="$ROUTER_USERNAME" \
	--build-arg SNMPV3_USER_B="$SNMPV3_USER" \
	--build-arg SNMPV3_AUTH_PASS_B="$SNMPV3_AUTH_PASS" \
	--build-arg SNMPV3_PRIV_PASS_B="$SNMPV3_PRIV_PASS" \
	--build-arg TUNNEL_USER_B="$TUNNEL_USER" \
	--build-arg TUNNEL_PASS_B="$TUNNEL_PASS" \
	--build-arg TUNNEL_ID_B="$TUNNEL_ID" \
	.
