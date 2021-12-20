if [ "$1" -ge 1 ]; then
  echo "$1"
fi
if [ "$1" = 0 ]; then
  systemctl daemon-reload
  [ -e "/var/run/<service>.sock" ] && rm "/var/run/<service>.sock"
fi
exit 0