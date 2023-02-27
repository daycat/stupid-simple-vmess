# Update
This project is no longer maintained.
I am no longer hosting the API required for this project. You can create your own API node with the code at https://github.com/daycat/daycatapi. You'll need to modify the script to use your new API endpoint in order for this to work.
# stupid-simple-vmess
the hands-down most simple Vmess script. No domain / knownledge / fiddling needed. 

# Usage

## IPv4 VPS:
```shell
wget 'https://api.daycat.me/rproxy/https://raw.githubusercontent.com/daycat/stupid-simple-vmess/main/install.sh' -O install.sh && bash install.sh
```

## IPv6-only VPS:
```shell
wget 'https://api.daycat.me/rproxy/https://raw.githubusercontent.com/daycat/stupid-simple-vmess/main/ipv6-only.sh' -O ipv6.sh && bash ipv6.sh
```

# To-do:
1. Auto detect if Apache is present, and if so, uninstall and kill apache (because it sucks)
2. Auto detect and kill any processes using port 80
3. Warn users on OVZ to open TUN/TAP if couldn't automatically open.
4. Combine scripts into one for easy management

# Credits
1. Thanks to [MisakaNO](https://rip.wiki/wiki/zzy/) for allowing me to modify his original script and publish this script
2. Thanks to [P3terX](https://github.com/P3TERX) for his wonderfully written Cloudflare Warp script that provides the possibility of IPv6-only VPSes being supported in this script
