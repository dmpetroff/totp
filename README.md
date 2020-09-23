# TOTP generator

This is my minimal-bullshit attempt to make life easier by
generating Google Authentication one time passwords locally
without need for smartphone.

### Building
Prerequisites:

- C99 compatible compiler
- glibc-2.19+ (on older glibc try adding `-D_BSD_SOURCE` to compiler flags)
- GNU make
- pkg-config
- libcrypto

After installing prerequisites just type
```
make
```
to build totp binary.

### Extracting secret from QR-code
Save screenshot of browser page with QR code before
importing it into Google Authenticator and

```
zbarimg --raw screenshot.png
```

`zbarimg` can be installed
- `apt-get zbar-tools` for Ubuntu
- `emerge media-gfx/zbar` for Gentoo
- build manually from https://github.com/mchehab/zbar

### Preparing secrets file
Program expects `~/.totp.csv` file with secrets and their names separated
by a single tab character (not spaces!).
```
# cat ~/.totp.csv
gmail   otpauth://totp/...
slack   otpauth://totp/...
vpn	otpauth://totp/...
```

### Using totp
After everything is prepared `./totp SECRET_NAME` will print 6-digit OTP code.

For example config from section above
```
./totp vpn
```
will print one time password for `vpn` secret.
