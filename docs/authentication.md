# Authentication

There are two possible authentication methods. A third one, hook authentication (delegating login to an external command), was removed in filebrowser-ng: it executed administrator-configured shell commands with attacker-controlled credentials in the environment (pre-authentication RCE, `CVE-2026-54088`) and let hook output escalate any login to admin. Use JSON or proxy auth instead.

## JSON Auth (default)

We call it JSON Authentication but it is just the default authentication method and the one that is provided by default if you don't make any changes. It is set by default, but if you've made changes before you can revert to using JSON auth:

```sh
filebrowser config set --auth.method=json
```

This method can also be extended with **reCAPTCHA** verification during login:

```sh
filebrowser config set --auth.method=json \
  --recaptcha.key site-key \
  --recaptcha.secret private-key
```

By default, we use [Google's reCAPTCHA](https://developers.google.com/recaptcha/docs/display) service. If you live in China, or want to use other provider, you can change the host with the following command:

```sh
filebrowser config set --recaptcha.host https://recaptcha.net
```

Where `https://recaptcha.net` is any provider you want.

## Proxy Header

If you have a reverse proxy you want to use to login your users, you do it via our `proxy` authentication method. To configure this method, your proxy must send an HTTP header containing the username of the logged in user:

```sh
filebrowser config set --auth.method=proxy --auth.header=X-My-Header
```

Where `X-My-Header` is the HTTP header provided by your proxy with the username.

> [!WARNING]
>
> filebrowser-ng only honors the header when the request arrives via a trusted proxy peer (`Server.TrustedProxies`, IPs/CIDRs matched against the direct TCP peer; forwarded headers are ignored because clients can spoof them). The default trusts loopback only (`127.0.0.0/8`, `::1`), which covers a co-located proxy. If your proxy runs on another host, configure it:
>
> ```sh
> filebrowser config set --trustedProxies=10.0.0.0/8,192.168.1.10
> ```
>
> Logins from any other peer are rejected, so a bypassed or missing proxy no longer yields admin access. The same trust check gates the expired-token waiver: a leaked token plus a spoofed header is useless off-proxy.

## No Authentication

We also provide a no authentication mechanism for users that want to use filebrowser-ng privately such in a home network. By setting this authentication method, the user with **id 1** will be used as the default users. Creating more users won't have any effect.

```sh
filebrowser config set --auth.method=noauth
```
