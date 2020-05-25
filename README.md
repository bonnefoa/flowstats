# Flowstats

## Download Latest Release

```
curl -o flowstats -SslL https://github.com/bonnefoa/flowstats/releases/latest/download/flowstats
chmod a+x flowstats
sudo setcap cap_net_raw,cap_net_admin=eip flowstats
```

## Launch Flowstats

```
# Listen to all interfaces on all ports
flowstats -i any

# Listen to eth0 on port 8080
flowstats -i eth0 -b "port 8080"

# Listen to all interfaces and display unknow fqdn
flowstats -i any -u
```

