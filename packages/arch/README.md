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

Photo uploads use ImageMagick 7 with libheif (AVIF) and libjxl (JPEG XL).
Set `photos.format` and `photos.quality` in the installed configuration;
the defaults are WebP at quality 85. Photos fit within 1024×1024, with
no stored originals or thumbnails. Social uploads retain their bytes.
