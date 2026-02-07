# f2bs

A focused, terminal UI for scanning Fail2Ban jails and unbanning IPs.

## Features

- Two-panel TUI (jails on the left, banned IPs on the right)
- Keyboard and mouse support
- Confirm prompt before unbanning
- Works directly with `fail2ban-client`

## Run

```bash
sudo f2bs
```

## Install (from GitHub release)

```bash
curl -fsSL https://raw.githubusercontent.com/hexajohnny/f2bs/main/install.sh | sudo sh
```

## Controls

- `q`: quit
- `r`: refresh
- `tab`: switch panels
- `enter`: unban selected IP
- `y/n`: confirm/cancel unban
- mouse click: select jail or IP, click Confirm/Cancel in modal

## Notes

- Requires `fail2ban-client` on PATH.
- Requires root privileges for unban operations. Run with `sudo f2bs`.

## License

f2bs is dual-licensed under MIT or Apache-2.0, matching the duviz project.
See `LICENSE-MIT` and `LICENSE-APACHE` in this folder.
