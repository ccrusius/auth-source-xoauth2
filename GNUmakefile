PKG := auth-source-xoauth2

$(PKG).elc: $(PKG).el
	emacs --no-init-file --no-site-file --batch --eval '(byte-compile-file "$<")'
