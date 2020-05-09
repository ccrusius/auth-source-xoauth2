# auth-source-xoauth2

This package adds `XOAuth2` authentication capabilities to `auth-source`.

This integration requires some preliminary work on the users' part, which
includes creating tokens that the package will use. For more details,

```
M-x describe-variable auth-source-xoauth2-creds
```

Note: This package _does_ work with Emacs 25.1, even though it requires 26.1 in
the package description. That requirement is necessary in order to silence
linter errors. If using Emacs 25.1, the `auth-source-pass` package is optional.

> Disclaimer: This is not an officially supported Google product.
