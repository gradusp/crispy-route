if [ "$1" -ge 1 ]; then
  systemctl stop <service>.service
fi
if [ "$1" = 0 ]; then
  systemctl disable --now <service>.service
fi
