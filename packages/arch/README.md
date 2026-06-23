# Arch Package

Build from this directory with:

```sh
makepkg -si
```

The package installs a systemd service named `unspoken.service`, creates
the `unspoken` system user, and creates `/var/lib/unspoken` through
systemd sysusers and tmpfiles hooks.

Edit `/etc/unspoken/config.yaml` before starting the service:

```sh
systemctl enable --now unspoken.service
```
